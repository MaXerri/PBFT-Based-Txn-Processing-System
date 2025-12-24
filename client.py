import asyncio
import json
from collections import deque
from typing import Tuple, Dict, Optional
import threading
import websockets
import traceback
from collections import defaultdict, Counter
import config

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

class Client:
    def __init__(
        self,
        name: str,
        nodes: Dict[int, Tuple[str, int]],
        listen_port: int,
        private_key,
        all_public_keys,
        leader_id: int = 1,
        timeout: float = 3,
    ):
        """
        Persistent-WebSocket Client.

        :param name: client name like 'A'
        :param nodes: mapping node_id -> (host, port)
        :param listen_port: (unused with websockets persistent outgoing connections, kept for compatibility/logging)
        :param private_key: client's private key object (cryptography)
        :param all_public_keys: mapping sender_id -> pem-bytes or already-loaded public key object
        :param leader_id: initially assumed leader id
        :param timeout: txn timeout (seconds)
        """
        self.name = name
        self.nodes = nodes
        self.listen_port = listen_port
        self.leader_id = leader_id
        self.timeout = timeout
        self.quorum_size = (len(nodes) // 3) + 1  # f+1
        

        # queue and state
        self.queue = deque()
        self.processing = False
        self.current_txn = None
        self.timeout_task: Optional[asyncio.Task] = None
        self.cancel_requested = False
        

        # crypto
        self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.all_public_keys = all_public_keys

        # persistent websocket connections to nodes: node_id -> websocket
        self.connections: Dict[int, websockets.WebSocketClientProtocol] = {}

        # asyncio loop in separate thread (keeps original structure)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)

        # internal background tasks container (so we can cancel if needed)
        self._bg_tasks = []

        # quorum counter for node replies
        self.replies: dict[float, list[dict]] = defaultdict(list)
        self.timestamp_to_transaction: dict[float, Tuple] = {}
        self.reply_locks = defaultdict(lambda: asyncio.Lock())

        self.start_time = -1.0

        # print(f"[Client {self.name}] Initialized (will connect to nodes).")

    # -------------------------
    # Event loop runner
    # -------------------------
    def start_loop(self):
        """Start the client's asyncio event loop in a separate thread. called by orchestrator after nodes initialized"""
        # print(f"[Client {self.name}] Starting event loop thread.")
        self.thread.start()
    
    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._start())
        except Exception:
            traceback.print_exc()
        finally:
            # Cancel outstanding tasks
            pending = asyncio.all_tasks(loop=self.loop)
            for t in pending:
                t.cancel()
            try:
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            self.loop.close()

    # -------------------------
    # Startup: connect to all nodes and keep connection tasks alive
    # -------------------------
    async def _start(self):
        # Connect to nodes
        await self.connect_to_nodes()
        # Keep running: nothing else to do here. The listen_node tasks handle incoming messages.
        # We'll also start the processing loop runner (consumer) that watches the queue.
        self._bg_tasks.append(asyncio.create_task(self._queue_watcher()))
        # keep the coroutine alive
        await asyncio.gather(*self._bg_tasks)

    async def connect_to_nodes(self):
        """
        Establish persistent websocket connections to every node and spawn listener tasks.
        If a connection fails, we continue (caller may retry later).
        """
        for node_id, (host, port) in self.nodes.items():
            uri = f"ws://{host}:{port}"
            try:
                ws = await websockets.connect(uri, ping_interval=None)
                self.connections[node_id] = ws
                task = asyncio.create_task(self.listen_node(ws, node_id))
                self._bg_tasks.append(task)
                # print(f"[Client {self.name}] Connected to node {node_id} at {uri}")
            except Exception as e:
                print(f"[Client {self.name}] Failed to connect to node {node_id} at {uri}: {e}")

    # -------------------------
    # Listening to node messages on the persistent ws connection
    # -------------------------
    async def listen_node(self, ws: websockets.WebSocketClientProtocol, node_id: int):
        """
        Reads messages from a node over its persistent websocket and calls verification/handler.
        """
        try:
            async for raw_msg in ws:
                try:
                    msg = json.loads(raw_msg)
                except Exception as e:
                    print(f"[Client {self.name}] Invalid JSON from node {node_id}: {e}")
                    continue

                # The node may identify itself either by "node" (string) or "sender" (node id).
                # We normalize to a sender_id string that matches keys in all_public_keys.
                sender = msg.get("node") or msg.get("sender") or node_id

                # verify and handle
                verified = await self._verify_incoming_from_node(msg, sender)
                if verified:
                    timestamp = msg.get("timestamp")
                    txn = self.timestamp_to_transaction.get(timestamp)

                    # print("trasnaction key:", txn)
                    # print(self.replies)
                    # deliver message to client state machine
                    if msg.get("type") == "READ-ONLY-REPLY":
                        # print(f"[Client {self.name}] Received READ-ONLY reply from node {node_id}: {msg}")
                        await self.handle_read_only_response(txn, msg)
                    else:
                        await self.receive_response(txn, msg, timestamp)
                else:
                    # verification failure already printed inside _verify_incoming_from_node
                    pass

        except websockets.ConnectionClosed as e:
            print(f"[Client {self.name}] WebSocket to node {node_id} closed: {e}")
        except Exception as e:
            print(f"[Client {self.name}] listen_node error for node {node_id}: {e}")
            traceback.print_exc()
        finally:
            # remove connection if present
            if node_id in self.connections and self.connections[node_id] is ws:
                del self.connections[node_id]

    # -------------------------
    # Verification helper for incoming node messages
    # -------------------------
    async def _verify_incoming_from_node(self, msg: dict, sender_key) -> bool:
        """
        Verify signature of a message received from a node (or client).
        sender_key may be a numeric id, e.g., 1, or string 'node1', or 'A'.
        all_public_keys keys should match the 'sender' used in messages.
        """

        signature_hex = msg.get("signature", "")
        if not signature_hex:
            # print(f"[Client {self.name}] Missing signature in message: {msg}")
            return False

        # decode signature (we expect hex here)
        try:
            signature = bytes.fromhex(signature_hex)
        except Exception:
            # print(f"[Client {self.name}] Signature not hex: {signature_hex}")
            return False

        # prepare canonical bytes of the message without signature
        msg_to_verify = {k: v for k, v in msg.items() if k != "signature"}
        msg_bytes = json.dumps(msg_to_verify, sort_keys=True, separators=(",", ":")).encode()

        # Resolve public key entry: allow numeric node id or 'nodeX' naming
        key_candidates = []
        # direct match
        if sender_key in self.all_public_keys:
            key_candidates.append(self.all_public_keys[sender_key])
        # try normalized name forms
        if isinstance(sender_key, int):
            name_form = f"node{sender_key}"
            if name_form in self.all_public_keys:
                key_candidates.append(self.all_public_keys[name_form])
        else:
            # sender might be numeric string or 'nodeX'; try 'node{n}' if msg gave '1'
            if isinstance(sender_key, str) and sender_key.isdigit():
                name_form = f"node{sender_key}"
                if name_form in self.all_public_keys:
                    key_candidates.append(self.all_public_keys[name_form])

        if not key_candidates:
            # print(f"[Client {self.name}] Unknown sender key {sender_key}. Known keys: {list(self.all_public_keys.keys())}")
            return False

        # Try each candidate (PEM bytes or loaded key)
        for pub_entry in key_candidates:
            try:
                if isinstance(pub_entry, (bytes, bytearray)):
                    pub = serialization.load_pem_public_key(pub_entry)
                else:
                    pub = pub_entry  # already an object
                pub.verify(signature, msg_bytes, ec.ECDSA(hashes.SHA256()))
                # success
                return True
            except Exception as e:
                # try next candidate; only log on final failure
                last_exc = e
                continue

        # if we get here, verification failed for all candidates
        # print(f"[Client {self.name}] Invalid signature from {sender_key}: {last_exc}")
        # print(f"[DEBUG] Signature bytes: {signature}")
        # print(f"[DEBUG] Message bytes: {msg_bytes}")
        return False

    # -------------------------
    # Transaction queue / processing
    # -------------------------
    def queue_transaction(self, txn: Tuple):
        """Add transaction to queue and ensure processing starts."""
        # print(f"[Client {self.name}] Queuing transaction: {txn}")
        # schedule addition onto the client's loop
        asyncio.run_coroutine_threadsafe(self._queue_put(txn), self.loop)

    async def _queue_put(self, txn: Tuple):
        self.queue.append(txn)
        # only start processing if not already in progress
        if not self.processing:
            self.processing = True
            await self._process_next()

    async def _queue_watcher(self):
        """
        Background task that keeps the event loop alive;
        previously start_listener blocked the loop. This is a simple placeholder
        that keeps process tasks running and can be expanded for reconnection logic.
        """
        while True:
            await asyncio.sleep(3600)

    async def _process_next(self):
        """Process next txn from the queue."""
        if not self.queue:
            self.processing = False
            self.current_txn = None
            # print(f"[Client {self.name}] No more transactions to process.")
            return

        txn_to_process = self.queue.popleft()
        self.processing = True
        self.cancel_requested = False

        # print(f"[Client {self.name}] Processing next transaction: {txn_to_process}")
        # If leader connection missing, try to reconnect once
        if self.leader_id not in self.connections:
            # attempt reconnect to leader
            host, port = self.nodes[self.leader_id]
            print("Error: BAAAD")

        # print(f"[Client {self.name}] Sending txn {self.current_txn} to node {self.leader_id}")

        if self.current_txn is not None:
            # read-only broadcast to all nodes
            await self.broadcast_request(txn_to_process)
        else:
            # fire-and-forget send to leader
            r_only = len(txn_to_process) == 1
            asyncio.create_task(self._send_to_node_ws(txn_to_process, self.leader_id, readonly=r_only))

        # Start timeout task
        if self.timeout_task:
            self.timeout_task.cancel()
        self.timeout_task = asyncio.create_task(self._transaction_timeout(txn_to_process))

    # -------------------------
    # WebSocket send (single node)
    # -------------------------
    async def _send_to_node_ws(self, txn: tuple, node_id: int, broadcast: bool = False, readonly: bool = False):
        """
        Build signed message and send over persistent websocket to node_id.
        """
        if node_id not in self.connections:
            # print(f"[Client {self.name}] No websocket for node {node_id}; cannot send {txn}")
            return

        
        msg = {
            "type": "REQUEST",
            "client": self.name,
            "txn": list(txn),
            "timestamp": f"{asyncio.get_event_loop().time():.6f}" if not broadcast else self.current_txn[-1],
            "readonly_broadcast": broadcast and readonly,
        }
        if not broadcast:
            self.current_txn = tuple(list(txn) + [msg["timestamp"]])

        self.replies[msg["timestamp"]] = []  # make empty list for this txn TODO check
        self.timestamp_to_transaction[msg["timestamp"]] = txn

        # canonical bytes and sign
        msg_bytes = self.canonical_json_bytes(msg)
        signature = self.private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
        msg["signature"] = signature.hex()

        self.start_time = asyncio.get_event_loop().time()
        if not readonly:
            ws = self.connections[node_id]
            try:
                await ws.send(json.dumps(msg))
                # fire-and-forget -> do not await any reply here
                # print(f"[Client {self.name}] Sent txn {txn} to node {node_id}")
            except Exception as e:
                print(f"[Client {self.name}] Error sending txn {txn} to node {node_id}: {e}")
        elif readonly and not broadcast:
            # multicast to all nodes
            for n_id in self.connections.keys():
                ws = self.connections[n_id]
                try:
                    await ws.send(json.dumps(msg))
                    # print(f"[Client {self.name}] Sent READONLY txn {txn} to node {n_id}")
                except Exception as e:
                    print(f"[Client {self.name}] Error sending READONLY txn {txn} to node {n_id}: {e}")

        elif readonly and broadcast:
            # send to leader as regular request
            ws = self.connections[node_id]
            try:
                await ws.send(json.dumps(msg))
                # fire-and-forget -> do not await any reply here
                # print(f"[Client {self.name}] Sent broadcasted readonly txn {txn} to node {node_id}")
            except Exception as e:
                print(f"[Client {self.name}] Error sending, txn {txn} to node {node_id}: {e}")
            

    async def broadcast_request(self, txn: tuple):
        """
        Send the given txn to all nodes (fire-and-forget).
        """
        # print(f"[Client {self.name}] Broadcasting txn {txn} to all nodes")
        for node_id in self.nodes.keys():
            # schedule each send without awaiting (fire-and-forget)
            asyncio.create_task(self._send_to_node_ws(txn, node_id, broadcast=True))

    # -------------------------
    # Helpers / verification utilities
    # -------------------------
    def canonical_json_bytes(self, msg: dict) -> bytes:
        return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()

    # -------------------------
    # Timeout & response handling
    # -------------------------
    async def _transaction_timeout(self, txn: Tuple):
        try:
            await asyncio.sleep(self.timeout)
            if len(txn) != 1 and (self.processing and self.current_txn[0:3] == txn):
                # print(f"[Client {self.name}] Timeout expired for txn {txn}; broadcasting to all nodes")
                await self.broadcast_request(txn)
            elif len(txn) == 1 and (self.processing and self.current_txn[0:1] == txn):
                # print(f"[Client {self.name}] Timeout expired for READ-ONLY txn {txn}; re-broadcasting to LEADER")
                await self._send_to_node_ws(txn, self.leader_id, broadcast=True, readonly=True)
            else:
                # print(f"[Client {self.name}] Timeout task for txn {txn} ended but txn already processed.")
                pass
        except asyncio.CancelledError:
            pass


    async def receive_response(self, txn: Tuple, msg: dict, timestamp: str):
        """
        Handle verified replies from replicas.
        Ensures atomic quorum checking using a per-transaction lock.
        """

        
        # print(f"[Client {self.name}] Received reply for txn {txn} from node: {msg}")
        async with self.reply_locks[tuple(txn)]:
            if msg["leader"] == True:
                self.leader_id = msg["sender"]  
            self.replies[timestamp].append(msg)

            finalize = False
            if len(self.replies[timestamp]) == self.quorum_size:
                config.latencies.append(asyncio.get_event_loop().time() - self.start_time)
                if self.timeout_task:
                    self.timeout_task.cancel()
                    self.timeout_task = None

                # print(f"[Client {self.name}] Transaction {txn} completed with reply: {msg}")
                self.processing = False
                self.current_txn = None
                finalize = True

        # Call outside the lock
        if finalize:
            await self._process_next()

    # -------------------------
    # Shutdown helpers (optional)
    # -------------------------
    async def close(self):
        # cancel background tasks & close websockets
        for t in list(self._bg_tasks):
            t.cancel()
        for node_id, ws in list(self.connections.items()):
            try:
                await ws.close()
            except Exception:
                pass
        self.connections.clear()


    # -------------------------
    # Cancel handling
    # -------------------------
    def handle_cancel(self):
        # print(f"[Client {self.name}] Cancel requested for {self.current_txn}")
        self.cancel_requested = True
        if self.timeout_task:
            self.timeout_task.cancel()
            self.timeout_task = None

        # clear states after ending set
        self.processing = False
        self.current_txn = None
        self.queue.clear()


    async def send_heartbeat(self):
        """
        Sends a lightweight heartbeat to all connected nodes.
        Fire-and-forget: does not wait for any response.
        """
        heartbeat_msg = {
            "type": "HEARTBEAT",
            "client": self.name
        }

        for node_id, ws in self.connections.items():
            try:
                # Fire-and-forget send
                asyncio.create_task(ws.send(json.dumps(heartbeat_msg)))
                # print(f"[Client {self.name}] Heartbeat sent to node {node_id}")
            except Exception as e:
                print(f"[Client {self.name}] Failed to send HEARTBEAT to node {node_id}: {e}")


    async def handle_read_only_response(self, txn, msg: dict):
        """
        Handle read-only replies from replicas.
        """

        
        # print(f"[Client {self.name}] Handling read-only response: {msg}")
        # Here you can implement specific logic for read-only responses,
        # such as updating client state or notifying the user.
        async with self.reply_locks[tuple(txn)]:
            if msg["leader"] == True:
                self.leader_id = msg["sender"]  
                
            self.replies[msg["timestamp"]].append((msg["sender"], msg["r"]))

            values = [r for _, r in self.replies[msg["timestamp"]]]
            counts = Counter(values)

            most_common_val, count = counts.most_common(1)[0]

            if count == 2 * (len(self.nodes) // 3) + 1:
                config.latencies.append(asyncio.get_event_loop().time() - self.start_time)
                # print(f"[Client {self.name}] Read-only transaction completed with value: {most_common_val}")
                # Clean up
                self.processing = False
                self.current_txn = None
                self.timeout_task.cancel()
                self.timeout_task = None

                await self._process_next()


