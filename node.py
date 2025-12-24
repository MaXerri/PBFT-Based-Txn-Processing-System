import asyncio
import json
import os
import csv
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from copy import deepcopy
from typing import Dict, Optional, Tuple
import hashlib
import websockets
from websockets import serve
from collections import defaultdict
import psutil
import time
from blspy import (
    PrivateKey as BLSPrivateKey,  # private key
    G1Element as BLSPublicKey,    # public key
    G2Element as BLSSignature,    # signature
    AugSchemeMPL,                  # signing and verification helper
    G2Element,
    G1Element
)

class Node:
    def __init__(self, node_id: int, port: int, main_port: int, nodes: dict[int, tuple[str, int]], client_addr: tuple[str, int],
                 private_key, all_public_keys, bls_node_key, bls_node_public_keys):
        """
        :param node_id: integer node id (1,2,3,...)
        :param port: TCP port this node listens on
        :param is_byzantine: whether this node behaves maliciously
        """
        self.node_id = node_id
        self.port = port
        self.main_port = main_port
        self.alive = True
        self.queued_requests = []  # list of transactions received
        self.requests_in_processing: Dict[Tuple[int, int, str], Tuple[str, str, int, str]] = {}  # set of transactions being processed: (view, seq, digest) -> (from_client, to_client, amount, timestamp)
        self.other_nodes = nodes  # node_id -> (host, port)
        self.is_byzantine = False 
        self.attack = None
        self.role = "LEADER" if self.node_id == 1 else "BACKUP"  # initial role for view 1 due to v mod n rule
        self.alive_pre_prompting = True
        self.client_addr = client_addr  # (host, port) of client to send responses to
        self.last_assigned_seq = 0  # last assigned sequence number
        self.last_executed_seq = 0  # last executed sequence number
        self.last_reply_per_client = {}  # client_name -> last reply sent
        self.f = (len(self.other_nodes) // 3)


        self.node_connections: dict[int, websockets.WebSocketClientProtocol] = {}  # node_id -> ws
        self.client_connections: dict[str, websockets.WebSocketClientProtocol] = {}  # client_name -> ws

        # sigs
        self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.all_public_keys = all_public_keys

        self.bls_node_key = bls_node_key
        self.bls_node_public_keys = bls_node_public_keys


        # timer & view
        self.current_view_timer: Optional[asyncio.Task] = None
        self.current_view: int = 1
        self.view_timeout: float = 4  # seconds
        self.view_change_messages: dict[int, list[dict]] = {}
        self.view_change_messages_w_invalids: Dict[int, list[dict]] = {}  # view -> set of VIEW-CHANGE msgs (including invalid)
        self.in_view_change: bool = False

        # prepares and preprepares
        self.pre_prepared_messages = {}  # (seq_num, view) -> preprepare msg
        self.prepared_messages: Dict[Tuple[int, int, str], set[dict]] = {}      # (view, seq, digest) -> set of prepare msgs
        self.prepare_locks = defaultdict(lambda: asyncio.Lock())  # seq_num -> asyncio.Lock
        self.sent_prepare_certs = {}     # type: dict[tuple[int,int,str], bool]
        self.prepare_timer_active: Dict[Tuple[int, int, str], bool] = {}  # seq_num -> bool
        self.prepare_timer_tasks: Dict[Tuple[int, int, str], asyncio.Task] = {}  # seq_num -> asyncio.Task

        # Key: tuple of (view, seq, digest)
        # Value: dict mapping replica_id (int) -> signed prepare message (dict)
        self.prepare_certificates: Dict[Tuple[int, int, str], Dict[int, dict]] = {}

        self.sent_commits: Dict[Tuple[int, int, str], bool] = {}
        # COMMIT certificates: key → dict(sender_id → commit_msg)
        self.commit_certificates: Dict[Tuple[int, int, str], Dict[int, dict]] = {}

        # Per-key locks to guard commit broadcast
        self.commit_locks = defaultdict(lambda: asyncio.Lock())

        self.sent_commit_certs: Dict[Tuple[int, int, str], bool] = {}

        self.committed_entries: set[Tuple[int, int, str]] = set()  # set of (view, seq, digest) committed     

        self.balances: Dict[str, int] = {}  # client_name -> balance
        for client_name in client_addr.keys():
            self.balances[client_name] = 10

        self.balance_file = os.path.join("storage", f"node_{self.node_id}_balances.csv")
        self.save_to_persistent(self.balances)


        self.executed_requests: Dict[int, Tuple[str, str, int, int]] = {}  # (view, seq_num, digest) -> (from_client, to_client, amount, timestamp)
        self.executed_readonly_non_seqs: set[Tuple[str, str, int, str]] = set()  # set of (from_client, to_client, amount, timestamp) for read-only txns

        self.log = "" 
        self.log_lock = asyncio.Lock()  
        self.new_view_log = []
        self.new_view_sent = set()
        self.new_view_received = set()
        self.new_view_lock = asyncio.Lock()

        self.checkpoint_interval = 10
        self.checkpoints_received: Dict[int, list[dict]] = {}  # int -> set(node_id)
        self.stable_checkpoints: list[int] = []  # list of seq_nums that are stable checkpoints

        # benechmarking
        self.benchmark_active = False
        self.benchmark_task = None

    def save_to_persistent(self, balance_dict: dict[str, float]):
        """
        Save a dictionary of client balances to persistent CSV storage.

        Args:
            balance_dict: dict mapping client names to balances
        """
        temp_file = f"{self.balance_file}.tmp"

        # Write to a temporary file first
        with open(temp_file, mode="w", newline="") as f:
            writer = csv.writer(f)
            for client, balance in balance_dict.items():
                writer.writerow([client, balance])

        # Atomically replace the old file
        os.replace(temp_file, self.balance_file)


    # ------------------------
    # WebSocket Connection Entry Point
    # ------------------------
    async def handle_ws_connection(self, websocket):
        """
        Handles incoming WebSocket connections from either clients or other nodes.
        Distinguishes message type dynamically.
        """
        # print(f"[Node n{self.node_id}] WebSocket connection established on {self.port}", flush=True)
        msg = None
        try:
            async for raw_data in websocket:
                try:
                    msg = json.loads(raw_data)
                except json.JSONDecodeError:
                    print(f"[Node n{self.node_id}] Invalid JSON received: {raw_data}")
                    continue

                msg_type = msg.get("type")

                # ALIVE messages ---
                if msg_type == "ALIVE":
                    # print(f"[Node n{self.node_id}] Received ALIVE message.")
                    await self.handle_alive(msg)
                    try:
                        await websocket.send(json.dumps({"status": "alive_ack"}))
                    except Exception as e:
                        print(f"[Node n{self.node_id}] Error sending ALIVE ack: {e}")
                    continue
                
                if msg_type == "HEARTBEAT":
                    # print(f"[Node n{self.node_id}] Received HEARTBEAT message.")
                    try:
                        await self.handle_client_heartbeat(msg, websocket)
                    except Exception as e:
                        print(f"[Node n{self.node_id}] Error handling HEARTBEAT: {e}")
                    continue

                if msg_type == "STATUS_REQUEST":
                    # print(f"[Node n{self.node_id}] Received STATUS message.")
                    reply_msg = await self.handle_status_request(msg)
                    await websocket.send(json.dumps(reply_msg))
                    continue

                if msg_type == "CANCEL":
                    try:
                        await self.handle_cancel(msg)
                    except Exception as e:
                        print(f"[Node n{self.node_id}] Error handling CANCEL: {e}")
                    continue

                # don't listern if node dead and stop processing
                if not self.alive:
                    # print(f"[Node n{self.node_id}] Node is down, ignoring message: {msg}")
                    continue 

                await self.print_to_log(msg)

                # Node-to-node protocol messages ---
                if msg_type in {"PRE-PREPARE", "PREPARE", "PREPARE-BROADCAST", "PREPARE-BROADCAST-OPT", "COMMIT", "COMMIT-BROADCAST", "VIEW-CHANGE", "NEW-VIEW", "CHECKPOINT"}:
                    # print(f"[Node n{self.node_id}] Node-to-node WS message received: {msg}")
                    await self.handle_node_ws(msg, websocket)
                    if msg_type == "COMMIT-BROADCAST":
                        # print(f"[Node n{self.node_id}] Finished handling COMMIT-BROADCAST: {msg}")
                        pass
                    continue

                # Client requests ---
                sender_id = msg.get("client")
                if not sender_id or not self.verify_signature(msg, sender_id):
                    # print(f"Node n{self.node_id}: Invalid or missing signature, ignoring message: {msg}")
                    continue

                await self.dispatch_client_message(msg, websocket)
                

        except websockets.exceptions.ConnectionClosed as e:
            # msg may be None if the recv failed before we parsed a message
            if msg is None:
                print(f"[Node n{self.node_id}] WebSocket connection closed (no last msg). exception: {e}", flush=True)
            else:
                print(
                    f"[Node n{self.node_id}] WebSocket connection closed. "
                    f"message from: {msg.get('client','unknown')}, {msg.get('sender','unknown')}, type - {msg.get('type','unknown')}. "
                    f"exception: {e}",
                    flush=True
                )
        except Exception as e:
            print(f"[Node n{self.node_id}] Error in WS handler: {e}")

        print(f"[Node n{self.node_id}] WebSocket handler exiting, msg type is {msg.get("type", "unknown")}", flush=True)


    async def print_to_log(self, msg: dict):
        """
        Log messages with locking.
        """
        msg_type = msg.get("type")
        # log message and locking
        async with self.log_lock:
            if msg_type == "REQUEST":
                self.log += f"<REQUEST,  {msg["txn"]}, {msg["timestamp"]}, {msg["client"]}>\n"
            elif msg_type == "PRE-PREPARE":
                self.log += f"<PRE-PREPARE,  {msg["view"]}, {msg["seq"]}, {msg["digest"]}> {msg["request"]} >\n"
            elif msg_type == "PREPARE":
                self.log += f"<PREPARE,  {msg["view"]}, {msg["seq"]}, {msg["digest"]}, n{msg["sender"]}>\n"
            elif msg_type == "PREPARE-BROADCAST":
                self.log += f"<PREPARE-BROADCAST,  {msg["view"]}, {msg["seq"]}, {msg["digest"]}, n{msg["sender"]}>\n"
            elif msg_type == "PREPARE-BROADCAST-OPT":
                self.log += f"<PREPARE-BROADCAST-OPT,  {msg["view"]}, {msg["seq"]}, {msg["digest"]}, n{msg["sender"]}>\n"
            elif msg_type == "COMMIT":
                self.log += f"<COMMIT, {msg["view"]}, {msg["seq"]}, {msg["digest"]}, n{msg["sender"]}>\n"
            elif msg_type == "COMMIT-BROADCAST":
                self.log += f"<COMMIT-BROADCAST,  {msg["view"]}, {msg["seq"]}, {msg["digest"]}, from n{msg["sender"]}>\n"
            elif msg_type == "REPLY":
                self.log += f"<{msg_type},  {self.current_view}, {msg["timestamp"]}, {msg["sender"]}, {self.node_id}, {msg["status"]}>\n"
            elif msg_type == "READ-ONLY-REPLY":
                self.log += f"<{msg_type},  {self.current_view}, {msg["timestamp"]}, {msg["client"]}, {self.node_id}, {msg["r"]}>\n"
            elif msg_type == "VIEW-CHANGE":
                self.log += self.view_change_to_string(msg)
            elif msg_type == "NEW-VIEW":
                log = self.new_view_to_string(msg)
                self.log += log
                self.new_view_log.append(log)

            elif msg_type == "CHECKPOINT":
                self.log += f"<CHECKPOINT,  {msg["seq"]}, {msg["digest"]}, {msg["sender"]}>\n"
            else:
                print("ERROR UNKNOWN MESSAGE HERE:",msg_type)


    # ------------------------
    # Client-facing messages
    async def dispatch_client_message(self, msg: dict, websocket):
        """
        Handle messages from clients connected via WebSockets.
        """
        if not self.alive:
            # print(f"Node n{self.node_id} is down, ignoring client message: {msg}")
            return

        msg_type = msg.get("type")
        txn = msg.get("txn")

        if msg_type == "REQUEST":
            self.start_view_timer()

            if len(msg["txn"]) == 1 and not msg.get("readonly_broadcast", False):
                # print(f"[Node n{self.node_id}] Received Read-only txn {txn}.")
                await self.handle_read_only_request(msg)
            
            elif len(msg["txn"]) == 1 and msg.get("readonly_broadcast", False):
                # print(f"[Node n{self.node_id}] Received Read-only Broadcast txn {txn}.")
                await self.handle_client_request(msg, websocket)

            else:
                await self.handle_client_request(msg, websocket)

        else:
            await websocket.send(json.dumps({"status": "unknown_type"}))

    # ------------------------
    # Node-to-node messages
    # ------------------------
    async def handle_node_ws(self, msg: dict, websocket):
        """
        Handles messages from other nodes via WebSockets.
        """
        try:
            sender_id = msg.get("sender")
            if sender_id is None or not self.verify_signature(msg, sender_id):

                if msg.get("type") == "PRE-PREPARE":
                    # print(f"Node n{self.node_id}: starting view timer from  invalid PRE-PREPARE")
                    self.start_view_timer() # still start timer type shit
                # print(f"Node n{self.node_id}: Invalid/missing signature from node {sender_id}, ignoring: {msg}")
                if msg.get("type") == "VIEW-CHANGE":
                    view = msg.get("view", -1)

                    if view not in self.view_change_messages_w_invalids:
                        self.view_change_messages_w_invalids[view] = []
                    self.view_change_messages_w_invalids[view].append(msg)
                   
                    await self.check_if_timer_needed(msg)
                return


            await self.dispatch_node_message(msg, websocket)

        except Exception as e:
            print(f"Node n{self.node_id} error handling node WS message: {e}")
            print(f"Message was: {msg}")

    async def dispatch_node_message(self, msg: dict, websocket):
        """
        Dispatch based on node message type.
        """
        msg_type = msg.get("type")
        response = {"status": "unknown_node_msg"}

        if msg_type == "PRE-PREPARE":
            # print(f"Node n{self.node_id} received PRE-PREPARE: {msg}")
            await self.handle_preprepare(msg)
            response = {"status": "preprepare_received"}

        elif msg_type == "PREPARE":
            # print(f"Node n{self.node_id} received PREPARE: {msg}")
            await self.handle_prepare(msg)
            response = {"status": "prepare_received"}

        elif msg_type == "PREPARE-BROADCAST":
            # print(f"Node n{self.node_id} received PREPARE-BROADCAST: {msg}")
            await self.handle_prepare_broadcast(msg)
            response = {"status": "prepare_broadcast_received"}

        elif msg_type == "PREPARE-BROADCAST-OPT":
            # print(f"Node n{self.node_id} received PREPARE-BROADCAST-OPT: {msg}")
            await self.handle_prepare_broadcast(msg, optimized=True)
            response = {"status": "prepare_broadcast_opt_received"}

        elif msg_type == "COMMIT":
            # print(f"Node n{self.node_id} received COMMIT: {msg}")
            await self.handle_commit(msg)
            response = {"status": "commit_received"}

        elif msg_type == "COMMIT-BROADCAST":
            # print(f"Node n{self.node_id} received COMMIT-BROADCAST: {msg}")
            await self.handle_commit_broadcast(msg)
            # print(f"Node n{self.node_id} finished handling COMMIT-BROADCAST: {msg}")
            response = {"status": "commit_broadcast_received"}

        elif msg_type == "VIEW-CHANGE":
            # print(f"Node n{self.node_id} received VIEW-CHANGE: {msg}")
            await self.handle_view_change_message(msg)
            response = {"status": "view_change_received"}

        elif msg_type == "NEW-VIEW":
            # print(f"Node n{self.node_id} received NEW-VIEW: {msg}")
            await self.handle_new_view(msg)
            response = {"status": "new_view_received"}

        elif msg_type == "CHECKPOINT":
            # print(f"Node n{self.node_id} received CHECKPOINT: {msg}")
            await self.handle_checkpoint(msg)
            response = {"status": "checkpoint_received"}

        # Send acknowledgement
        try:
            asyncio.create_task(websocket.send(json.dumps(response)))
        except Exception as e:
            print(f"Node n{self.node_id} error sending WS response: {e}")


    def view_change_to_string(self, msg) -> str:
        """
        Convert the P structure in VIEW-CHANGE messages to a readable string.
        P is a dict mapping (view, seq) tuples to pre-prepare messages.
        """

        p = msg.get("P")
        # print("p:", p)
        p_strings = "{\n"
        for pair in p:
            # print("pair:", pair)
            pp = pair[1]
            prepare_broadcast = pair[2]
            p_strings += f"[<PRE-PREPARE,  {pp["view"]}, {pp["seq"]}, {pp["digest"]}> {pp["request"]} >, <PREPARE-BROADCAST,  {prepare_broadcast["view"]}, {prepare_broadcast["seq"]}, {prepare_broadcast["digest"]}, from n{prepare_broadcast["sender"]}>]\n"

        p_strings += "}"

        c_set = msg.get("C")
        # print("c_set:", c_set)
        c_string = "{"
        for pair in c_set:
            # print("pair:", pair)
            c_string += f"<CHECKPOINT, {pair["seq"]}, {pair["digest"][0:10]}..., from n{pair["sender"]}>; "
        c_string += "}"

        return f"<VIEW-CHANGE,  {msg["view"]}, {msg["n"]} , {c_string} , {p_strings} , {msg["sender"]}>\n"

    def new_view_to_string(self, msg) -> str:

        v_set = msg.get("V")
        V = "{\n"
        for vc_msg in v_set:
            res = self.view_change_to_string(vc_msg)
            # print("res:", res)
            V += res
        V += "}"

        o_set = msg.get("O")
        # print("o_set:", o_set)
        O = "{\n"
        for pp_msg in o_set:
            O += f"<PRE-PREPARE,  {pp_msg["view"]}, {pp_msg["seq"]}, {pp_msg["digest"]}, from n{pp_msg["sender"]}>\n"
        O += "}"

        return f"<NEW-VIEW,  {msg["view"]}, {V}, {O}>\n END OF NEW-VIEW message\n\n"



# =========================================================================================
# ==================Sending Message (To client and nodes) + Helpers ========================
    # -------------------------
    # Helper: canonicalize and sign (or corrupt)
    # -------------------------
    def _prepare_message_bytes(self, msg: dict) -> tuple[dict, bytes]:
        """
        Returns (msg_copy_no_sig, canonical_bytes).
        Deterministic canonicalization: sort_keys + compact separators.
        """
        msg_copy = deepcopy(msg)
        msg_copy.pop("signature", None)
        msg_bytes = json.dumps(msg_copy, sort_keys=True, separators=(",", ":")).encode()
        return msg_copy, msg_bytes


    def _attach_signature(self, msg_copy: dict, msg_bytes: bytes, msg_to_send = None) -> dict:
        """
        Attach a signature to msg_copy:
        - If attacks['sign'] is set, attach bogus bytes for all message types.
        - If msg_copy['type'] == "COMMIT": create a BLS partial signature using this node's bls_node_key.
        - Otherwise: sign with ECDSA as before.

        Assumes:
        - self.bls_node_key exists (BLSPrivateKey from blspy) for COMMIT messages.
        - self.private_key exists (cryptography EC key) for other messages.
        """

        attacks = getattr(self, "attack", {}) or {}
        msg_copy.pop("signature", None)

        # Global malicious signature attack
        if self.attack is not None and self.attack.get("sign", False):
            bogus = os.urandom(64)
            msg_copy["signature"] = bogus.hex()
            # print(f"[Node {self.node_id} ATTACK] Attaching bogus signature:", bogus.hex())
            return msg_copy
    
        msg_type = msg_copy.get("type", "").upper()


        # ---- COMMIT messages: BLS partial signature ----
        if msg_type == "COMMIT" or msg_type == "PREPARE":
            if not hasattr(self, "bls_node_key") or self.bls_node_key is None:
                raise RuntimeError("No BLS node key available for partial COMMIT signing")

            try:
                # Exclude 'sender' from the bytes that are signed
                msg_to_sign = {k: v for k, v in msg_copy.items() if k not in ("signature", "sender")}
                # print("message to be signed:", msg_to_sign)
                msg_bytes_for_signing = self.canonical_json_bytes(msg_to_sign)

                #print("[DEBUG] Partial COMMIT signing")
                #print("  msg_to_sign:", msg_to_sign)
                #print("  msg_bytes_for_signing (hex):", msg_bytes_for_signing.hex())


                # Sign message bytes with BLS private key (partial)
                partial_sig = AugSchemeMPL.sign(self.bls_node_key, msg_bytes_for_signing)

                # print("message bytes for signing original commit: " + msg_bytes_for_signing.hex())

                # print("  partial_sig length:", len(bytes(partial_sig)))

                # Serialize to bytes and hex-encode
                msg_copy["signature"] = bytes(partial_sig).hex()

                msg_copy_without_sig = {k: v for k, v in msg_copy.items() if k != "signature" and k != "sender"}
                # print("[DEBUG] COMMIT message with partial signature bytes (no sig):", self.canonical_json_bytes(msg_copy_without_sig).hex())


                return msg_copy

            except Exception as e:
                raise RuntimeError(f"BLS partial signing failed: {e}") from e


        elif msg_type == "COMMIT-BROADCAST" or msg_type == "PREPARE-BROADCAST":
            if msg_to_send is None:
                raise RuntimeError("msg_to_send is required for COMMIT-BROADCAST")

            key = (msg_to_send["view"], msg_to_send["seq"], msg_to_send["digest"])

            if msg_type == "COMMIT-BROADCAST":
                commits = self.commit_certificates.get(key)
            else:
                commits = self.prepare_certificates.get(key)

            if not commits:
                raise RuntimeError(f"No partial commits found for threshold signing {key}")

            # print(f"[DEBUG] Threshold signing COMMIT-BROADCAST for key {key}")

            # Collect partial signatures in sorted sender_id order
            partial_sigs = []
            sorted_senders = sorted(commits.keys())
            for sender_id in sorted_senders:
                commit_msg = commits[sender_id]
                sig_bytes = bytes.fromhex(commit_msg["signature"])
                if len(sig_bytes) != 96:
                    raise RuntimeError(f"Invalid partial signature length from node {sender_id}")
                partial_sigs.append(G2Element.from_bytes(sig_bytes))
                # print(f"[DEBUG] sender {sender_id} sig_bytes len:", len(sig_bytes))
                # print(f"[DEBUG] sender {sender_id} sig_bytes (hex):", sig_bytes.hex())

            # Check quorum
            quorum_needed = 2*self.f if msg_type == "PREPARE-BROADCAST" else 2*self.f + 1
            if len(partial_sigs) < quorum_needed:
                raise RuntimeError(f"Not enough partial commits to aggregate: {len(partial_sigs)}/{quorum_needed}")

            # Aggregate signatures
            agg_sig = AugSchemeMPL.aggregate(partial_sigs)
            msg_to_send["signature"] = bytes(agg_sig).hex()
            msg_to_send["signers"] = sorted_senders

            # Debug: reconstructed COMMIT bytes for verification
            reconstructed_commit = {
                "type": "COMMIT" if msg_type == "COMMIT-BROADCAST" else "PREPARE",
                "view": msg_to_send["view"],
                "seq": msg_to_send["seq"],
                "digest": msg_to_send["digest"]
            }
            msg_bytes = self.canonical_json_bytes(reconstructed_commit)
            # print("[DEBUG] Reconstructed COMMIT bytes for threshold signing (hex):", msg_bytes.hex())
            # print("[DEBUG] Aggregated signature bytes (hex):", bytes(agg_sig).hex())

            return msg_to_send


        # ---- Default: ECDSA signing ----
        if not hasattr(self, "private_key") or self.private_key is None:
            raise RuntimeError("No ECDSA private_key available for signing")

        sig = self.private_key.sign(msg_bytes, ec.ECDSA(hashes.SHA256()))
        msg_copy["signature"] = sig.hex()
        return msg_copy


    # -------------------------
    #send to node (fire-and-forget)
    # -------------------------
    async def send_to_node(self, target_node_id: int, msg: dict, forwarded_req: bool = False) -> dict:
        """
        Fire-and-forget send to another node. Apply attacks/signing/equivocation/dark/time/crash logic.
        Returns a small status dict describing I/O outcome (not protocol reply).
        """
        # existence check
        if target_node_id not in getattr(self, "other_nodes", {}):
            print(f"[Node {self.node_id}] Unknown target node: {target_node_id}")
            return {"status": "error", "error": "unknown_target"}

        host, port = self.other_nodes[target_node_id]
        msg_type = msg.get("type", "").upper()

        attacks = getattr(self, "attack", {}) or {}
        
        # 1) in-dark: skip send to nodes in dark set
        # print(f"[Node {self.node_id}] attacks:", attacks)
        if attacks.get("dark") and target_node_id in attacks.get("dark_set", set()):
            # print(f"[Node {self.node_id}] Skipping {msg_type} to node {target_node_id} (dark)")
            return {"status": "skipped_in_dark", "target": target_node_id}

        # 2) crash: malicious replica may skip sending some message types
        if attacks.get("crash"):
            if getattr(self, "role", None) == "LEADER":
                if msg_type in ("PREPARE-BROADCAST", "PREPARE-BROADCAST-OPT", "NEW-VIEW") or (msg_type == "REPLY" and msg.get("read_only", False)):
                    # print(f"[Node {self.node_id}] crash attack by leader - stopping send ")
                    return {"status": "skipped_crash_leader", "type": msg_type}
            else:
                if msg_type in ("PREPARE") or (msg_type == "REPLY" and msg.get("read_only", False)):
                    # print(f"[Node {self.node_id}] crash attack by backup - stopping send ")
                    return {"status": "skipped_crash_backup", "type": msg_type}
            # print(f"[Node {self.node_id}] crash attack ... ")

        # 3) timing attack: optional delay
        if attacks.get("time"):
            delay = 0.5
            # print(f"[Node {self.node_id}] Timing attack: delaying {msg_type} to node {target_node_id} by {delay} seconds")
            await asyncio.sleep(delay)
            # print(f"[Node {self.node_id}] Timing attack: resuming {msg_type} to node {target_node_id}")

        # 4) equivocation (leader): modify seq numbers per-target
        msg_to_send = deepcopy(msg)
        if attacks.get("equivocation") and getattr(self, "role", None) == "LEADER" and msg_type == "PRE-PREPARE":
            equiv_set = attacks.get("equivocation_set", set())
            if "seq" in msg_to_send:
                base_seq = int(msg_to_send.get("seq", 0))
                msg_to_send["seq"] = base_seq if target_node_id in equiv_set else base_seq + 1


        # 5) prepare message bytes and sign (or corrupt)
        try:
            if not forwarded_req:
                msg_copy, msg_bytes = self._prepare_message_bytes(msg_to_send)
                msg_signed = self._attach_signature(msg_copy, msg_bytes, msg_to_send)
            else:
                msg_signed = msg_to_send  # forwarded request, do not resign
        except Exception as e:
            print(f"[Node {self.node_id}] Error preparing message: {e}")
            return {"status": "error", "error": f"signing/prepare_failed: {e}"}

        # get the existing WebSocket connection
        ws = self.node_connections.get(target_node_id)
        if not ws:
            print(f"[Node {self.node_id}] Error - No websocket connection to node {target_node_id}")
            return {"status": "error", "error": "no websocket connection", "target": target_node_id}

        # send the message (fire-and-forget)
        try:
            # print(f"[Node {self.node_id}] Sending {msg_type} to node {target_node_id}: {msg_signed}")
            await ws.send(json.dumps(msg_signed))
            return {"status": "sent", "target": target_node_id}
        except Exception as e:
            # optionally mark the connection broken
            # self.node_connections.pop(target_node_id, None)
            print(f"[Node {self.node_id}] Error sending {msg_type} to node {target_node_id}: {e}")
            return {"status": "error", "error": str(e), "target": target_node_id}

        

    # -------------------------
    # Fire-and-forget reply to client
    # -------------------------
    async def send_reply_to_client(self, client_name: str, msg: dict) -> dict:
        """Sign & send a reply message to the given client; do not wait for a response."""

        
        client_connections = getattr(self, "client_connections", {}) or {}
        ws = client_connections.get(client_name)
        if not ws:
            print(f"[Node {self.node_id}] No websocket connection to client {client_name}")
            return {"status": "error", "error": "no websocket connection to client", "client": client_name}

        try:
            msg_copy, msg_bytes = self._prepare_message_bytes(msg)
            msg_signed = self._attach_signature(msg_copy, msg_bytes)
        except Exception as e:
            print(f"[Node {self.node_id}] Error preparing/signing message for client {client_name}: {e}")
            return {"status": "error", "error": f"prepare/sign_failed: {e}"}

        try:
            # print(f"[Node {self.node_id}] Sending reply to client {client_name}: {msg_signed}")
            asyncio.create_task(ws.send(json.dumps(msg_signed)))
            return {"status": "sent", "client": client_name}
        except Exception as e:
            # optionally remove broken connection
            # client_connections.pop(client_name, None)
            print("Error:  BAAAAD")
            return {"status": "error", "error": str(e), "client": client_name}


    async def safe_send(self, target_node_id: int, msg: dict, forwarded_req: bool = False):
        """
        Wrapper around send_to_node with exception handling.
        """
        try:
            return await self.send_to_node(target_node_id, msg, forwarded_req)
        except Exception as e:
            print(f"[Node {self.node_id}] Exception in safe_send to node {target_node_id}: {e}")

    # ------------------------
    # Utilities
    # ------------------------

    async def connect_to_all_nodes(self):

        for node_id, (host, port) in self.other_nodes.items():
            if node_id == self.node_id:
                continue  # skip self
            try:
                uri = f"ws://{host}:{port}"
                ws = await websockets.connect(
                    uri, 
                    ping_interval=1000,
                    ping_timeout=2,
                    close_timeout=2
                )
                self.node_connections[node_id] = ws
                # print(f"[Node {self.node_id}] Connected to node {node_id}")
            except Exception as e:
                print(f"[Node {self.node_id}] Failed to connect to node {node_id}: {e}")

  

    async def run_ws_server(self):
        """
        Start a WebSocket server for node-to-node messages.
        """
        server = await websockets.serve(
            self.handle_ws_connection,  # no lambda, no path
            '127.0.0.1',
            self.port,
            ping_interval=1000,
            ping_timeout=2,
            close_timeout=2
        )
        # print(f"Node n{self.node_id} WS server listening on port {self.port}")
        await server.wait_closed()

    async def handle_alive(self, msg: dict):
        """
        Handle ALIVE message from client. Inclusing Byzantine setup
        """

        if msg["prompting_pause"]:
            self.alive_pre_prompting = self.alive
            self.benchmark_active = False
        else:
            self.benchmark_active = True
            self.benchmark_task = asyncio.create_task(self.run_node_benchmark())


        if msg["byzantine"]:
            self.is_byzantine = True
            self.attack = msg["attacks"]
            # print(f"[Node n{self.node_id}] I am set to Byzantine with attacks: {self.attack}.")
        else:
            self.is_byzantine = False
            self.attack = {}


        if msg["alive"]:
            if not self.alive:
                # print(f"[Node n{self.node_id}] Coming back up.")
                pass
            
            self.reset_state()
            self.alive = True

        elif not msg["alive"]:
            if self.alive:
                # print(f"[Node n{self.node_id}] Going down as per instruction.")
                pass
            if not msg["prompting_pause"]:
                self.reset_state()
            self.alive = False
            self.stop_view_timer()

        else:
            print("something suspicious is happening with ALIVE")

    def reset_state(self):
        """
        Reset the node's internal state when coming back to life.
        """

        # do not clear connections
        self.queued_requests.clear()
        self.requests_in_processing.clear()
        self.last_assigned_seq = 0
        self.last_executed_seq = 0
        self.last_reply_per_client.clear()
        self.current_view_timer = None
        self.current_view = 1
        self.role = "LEADER" if self.node_id == 1 else "BACKUP" 
        self.view_change_messages.clear()
        self.view_change_messages_w_invalids.clear()
        self.in_view_change = False
        self.pre_prepared_messages.clear()
        self.prepared_messages.clear()
        self.prepare_locks.clear()
        self.prepare_timer_active.clear()
        for _, timer in self.prepare_timer_tasks.items():
            if timer:
                timer.cancel()
        self.prepare_timer_tasks.clear()
        self.sent_prepare_certs.clear()
        self.prepare_certificates.clear()
        self.sent_commits.clear()
        self.commit_certificates.clear()
        self.commit_locks.clear()
        self.sent_commit_certs.clear()
        self.committed_entries.clear()
        self.balances = {client_name: 10 for client_name in self.client_addr.keys()}
        self.executed_requests.clear()
        self.executed_readonly_non_seqs.clear()
        self.checkpoints_received.clear()
        self.stable_checkpoints.clear()
        self.log = ""
        self.new_view_log = []
        self.new_view_sent = set()
        self.new_view_received = set()

        #self.benchmark_active = False
        #self.benchmark_task = None
        
        


    async def handle_client_heartbeat(self, msg: dict, websocket):
        """
        Handle a heartbeat from a client and store the websocket connection.
        Fire-and-forget: no ACK is sent back.
        """
        client_name = msg.get("client")
        if not client_name:
            # print(f"[Node {self.node_id}] Received HEARTBEAT with no client ID: {msg}")
            return

        # Save or update the websocket for this client
        if client_name not in self.client_connections:
            self.client_connections[client_name] = websocket
            # print(f"[Node {self.node_id}] Recorded websocket for client {client_name}")
    

    def canonical_json_bytes(self, msg: dict) -> bytes:
        return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()


    def verify_signature(self, msg: dict, sender_id: str) -> bool:
        """
        Verify the signature of a message, branching on message type:

        - COMMIT: verify BLS partial signature from the sender node
        - COMMIT-BROADCAST: verify threshold BLS signature
        - other types: default ECDSA signature verification

        sender_id: string or node ID corresponding to all_public_keys
        """
        signature_hex = msg.get("signature", "")
        if not signature_hex:
            return False

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False

        msg_type = msg.get("type", "").upper()

        # Remove signature field for canonical verification
        msg_to_verify = {k: v for k, v in msg.items() if k != "signature"}
        msg_bytes = self.canonical_json_bytes(msg_to_verify)

        # --- COMMIT: BLS partial signature verification ---
        if msg_type == "COMMIT" or msg_type == "PREPARE":
            try:
                if sender_id not in self.bls_node_public_keys:
                    print(f"Unknown BLS public key for node {sender_id}")
                    return False

                bls_pk = self.bls_node_public_keys[sender_id]  # G1Element
                partial_sig = G2Element.from_bytes(signature_bytes)  # Deserialize signature

                # Exclude 'sender' when reconstructing the canonical bytes for verification
                msg_to_verify = {k: v for k, v in msg.items() if k not in ("signature", "sender")}
                msg_bytes = self.canonical_json_bytes(msg_to_verify)

                if AugSchemeMPL.verify(bls_pk, msg_bytes, partial_sig):
                    # print(f"Valid BLS partial signature from {sender_id}")
                    return True
                else:
                    # print(f"Invalid BLS partial signature from {sender_id}")
                    return False

            except Exception as e:
                # print(f"BLS partial signature verification error: {e}")
                return False
            
        # --- COMMIT-BROADCAST: threshold signature verification ---
        elif msg_type == "COMMIT-BROADCAST" or msg_type == "PREPARE-BROADCAST":
            signers = msg.get("signers", [])
            if not signers:
                # print("[DEBUG] No signers provided in COMMIT-BROADCAST")
                return False

            # print(f"[DEBUG] Signers in COMMIT-BROADCAST: {signers}")

            # Collect the G1 public keys of the quorum signers
            pubkeys = []
            for node_id in signers:
                pk = self.bls_node_public_keys.get(node_id)
                if pk is None:
                    # print(f"[DEBUG] Missing public key for signer {node_id}")
                    return False

                if isinstance(pk, str):
                    pk = G1Element.from_bytes(bytes.fromhex(pk))
                elif isinstance(pk, (bytes, bytearray)):
                    pk = G1Element.from_bytes(bytes(pk))
                elif not isinstance(pk, G1Element):
                    # print(f"[DEBUG] Unsupported public key type for signer {node_id}")
                    return False

                pubkeys.append(pk)
                # print(f"[DEBUG] Signer {node_id} PK as G1Element bytes (hex): {bytes(pk).hex()}")

            # Construct canonical COMMIT message bytes
            msg_bytes = self.canonical_json_bytes({
                "type": "COMMIT" if msg_type == "COMMIT-BROADCAST" else "PREPARE",
                "view": msg["view"],
                "seq": msg["seq"],
                "digest": msg["digest"]
            })
            # print("[DEBUG] Reconstructed COMMIT message bytes for verification (hex):", msg_bytes.hex())

            # Load aggregated threshold signature from message
            signature_bytes = msg.get("signature")
            if not signature_bytes:
                # print("[DEBUG] Aggregated signature missing in COMMIT-BROADCAST")
                return False

            if isinstance(signature_bytes, str):
                signature_bytes = bytes.fromhex(signature_bytes)

            agg_sig = G2Element.from_bytes(signature_bytes)
            # print("[DEBUG] Aggregated threshold signature bytes (hex):", signature_bytes.hex())

            # Verify threshold signature using aggregate_verify
            try:
                messages = [msg_bytes] * len(pubkeys)  # same message for each signer
                result = AugSchemeMPL.aggregate_verify(pubkeys, messages, agg_sig)
                # print(f"[DEBUG] Threshold BLS signature verification result: {result}")
                return result
            except Exception as e:
                # print(f"[DEBUG] Threshold BLS signature verification error: {e}")
                return False


        # --- Default: ECDSA verification ---
        else:
            try:
                public_key = self.all_public_keys[sender_id]
                public_key.verify(signature_bytes, msg_bytes, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception as e:
                # print(f"Invalid ECDSA signature or structure: {e}")
                return False
        

    def aggregated_bls_pubkeys_for_commit(self, commit_msg: dict) -> G1Element:
        """
        Compute the aggregated public key from the BLS public keys of the nodes
        that participated in the COMMIT-BROADCAST.
        """
        signers = commit_msg.get("signers", [])
        if not signers:
            raise RuntimeError("No signers listed in COMMIT-BROADCAST")

        agg_pk = None
        for node_id in signers:
            if node_id not in self.bls_node_public_keys:
                raise RuntimeError(f"Unknown BLS public key for node {node_id}")

            pk = self.bls_node_public_keys[node_id]  # already a G1Element
            agg_pk = pk if agg_pk is None else agg_pk + pk

        return agg_pk
    
# ========================== TIMER AND VC LOGIC =========================



    def start_view_timer(self):
        """Start a view timer if none is running."""
        if self.current_view_timer is None:
            self.current_view_timer = asyncio.create_task(
                self._view_timer_task(self.current_view)
            )
            # print(f"[Node {self.node_id}] View timer started")

    def stop_view_timer(self):
        """Stop the current view timer, if running."""
        if self.current_view_timer:
            self.current_view_timer.cancel()
            self.current_view_timer = None
            # print(f"[Node {self.current_view}] View timer stopped")

    def reset_view_timer_if_pending(self):
        """Restart the timer if there are pending requests."""
        self.stop_view_timer()
        if self.has_pending_request():
            self.start_view_timer()

    def has_pending_request(self) -> bool:
        """Check if there are pending requests in the queue or being processed."""
        return len(self.queued_requests) > 0 or len(self.requests_in_processing) > 0

    async def _view_timer_task(self, view):
        """Coroutine that triggers a view-change after timeout unless cancelled."""
        try:
            await asyncio.sleep(self.view_timeout)
            # print(f"[Node {self.node_id}] View timer expired, initiating view change")
            await self.initiate_view_change(view)
        except asyncio.CancelledError:
            # Timer was cancelled, nothing to do
            # print(f"[Node {self.node_id}] View timer cancelled")
            pass


    async def initiate_view_change(self, view):
        """This is where you handle sending view-change messages to other replicas."""
        # print(f"[Node {self.node_id}] Initiating view change. currently in view {view}")

        # Implement your view-change logic here
        self.in_view_change = True
        await self.send_view_change()


    async def handle_view_change_message(self, msg: dict):
        """Process an incoming VIEW-CHANGE message."""
        view = msg.get("view")
        send = False
        if view is None:
            # print(f"[Node {self.node_id}] Malformed VIEW-CHANGE message: {msg}")
            return
        
        async with self.new_view_lock:
            self.record_view_change_message(view, msg)
            # If I am the new primary and quorum reached, fire-and-forget send NEW-VIEW
            if (msg["view"] % len(self.other_nodes) == self.node_id or (msg["view"] % len(self.other_nodes) == 0 and self.node_id == len(self.other_nodes) - 1)) \
                and self.has_view_change_quorum(view) and msg["view"] not in self.new_view_sent:

                self.new_view_sent.add(view)
                # print(f"[Node {self.node_id}] I am the new primary for view {view}, sending NEW-VIEW")
                send = True

            await self.check_if_timer_needed(msg)


        if send:        
            asyncio.create_task(self.send_new_view(view))

        return 

    async def check_if_timer_needed(self, msg: dict):
        # print(f"[Node {self.node_id}] hit check, v {msg.get('view')}, len vc w invalids: {len(self.view_change_messages_w_invalids.get(msg.get('view'), []))}")
        view = msg.get("view")
        if (len(self.view_change_messages_w_invalids.get(view, [])) >= 2 * self.f + 1) and msg["view"] not in self.new_view_received: # and self.role != "LEADER":
            # print(f"[Node {self.node_id}] Received quorum for VIEW-CHANGE for view {view}, starting timer to wait for nv")
            # TODO: start a timer to wait for NEW-VIEW and if expires, start view_change for v + 2 but with 2t wait
            self.reset_view_timer_if_pending()

    async def send_view_change(self):
        """Fire-and-forget send a VIEW-CHANGE to all other nodes."""

        last_stable_cp = 0 
        if len(self.stable_checkpoints) > 0:
            last_stable_cp = self.stable_checkpoints[-1]

        self.current_view = self.current_view + 1
        msg = {
            "type": "VIEW-CHANGE",
            "view": self.current_view,
            "n": last_stable_cp,
            "C": [] if last_stable_cp == 0 else self.checkpoints_received[last_stable_cp],
            "P": [], # list of tuples (preprepare, set of prepares)
            "sender": self.node_id,
        }

        # construct P:
        for ((view, seq_num, d), prepare_msgs) in  self.prepared_messages.items():
            # only include if seq_num > last stable checkpoint
            if seq_num > last_stable_cp:
                preprepare_msg = self.pre_prepared_messages.get((view, seq_num))
                if preprepare_msg is None:
                    # print(f"[Node {self.node_id}] Warning: missing preprepare for prepared message {(view, seq_num, d)}")
                    continue
                msg["P"].append((seq_num, preprepare_msg, prepare_msgs))

        try:
            msg_copy, msg_bytes = self._prepare_message_bytes(msg)
            msg_signed = self._attach_signature(msg_copy, msg_bytes)
        except Exception as e:
            # rint(f"[Node {self.node_id}] Failed to prepare/sign VIEW-CHANGE: {e}")
            return
        

        for node_id in self.other_nodes:
            if node_id == self.node_id:
                self.record_view_change_message(self.current_view, msg_signed) # record your own message 
                await self.print_to_log(msg)
                continue
            # fire-and-forget send
            asyncio.create_task(self.safe_send(node_id, deepcopy(msg_signed)))

        # print(f"[Node {self.node_id}] Sent VIEW-CHANGE for view {self.current_view}")


    async def send_new_view(self, view: int):
        """Fire-and-forget NEW-VIEW message with proof of 2f+1 view-change messages."""
        V = self.view_change_messages.get(view, [])

        # construct O:
        O = []
        min_s, max_s = self.compute_min_max_seq(V)
        for seq in range(min_s + 1, max_s + 1):
            msg_found = False
            for vc_msg in V:
                for seq_num, preprepare_msg, prepares in vc_msg.get("P", []):
                    if seq_num == seq:
                        O.append(preprepare_msg)
                        msg_found = True
                        break
                if msg_found:
                    break
            if not msg_found:
                # create null preprepare
                O.append(self.create_null_preprepare(seq, view))

        # add alll entries of o to requests in processing
        for pp_msg in O:
            self.requests_in_processing[(view, pp_msg["seq"], pp_msg["digest"])] = pp_msg["request"]

        msg = {
            "type": "NEW-VIEW",
            "view": view,
            "sender": self.node_id,
            "V": V,
            "O": O  # preprepared messages without piggybacked requests
        }

        # clear requests in processing for prior view
        keys_to_remove = [key for key in self.requests_in_processing if key[0] < view]
        for key in keys_to_remove:
            self.requests_in_processing.pop(key, None)

        msg_copy, msg_bytes = self._prepare_message_bytes(msg)
        msg_signed = self._attach_signature(msg_copy, msg_bytes)

        for node_id in self.other_nodes:
            if node_id == self.node_id:
                self.current_view = view
                await self.print_to_log(msg)
                continue
            # fire-and-forget send
            asyncio.create_task(self.safe_send(node_id, msg_signed))

        # print(f"[Node {self.node_id}] Sent NEW-VIEW for view {view}")
        # print("O: ", O)
        self.current_view = view
        self.role = "LEADER"
        self.last_assigned_seq = max_s

        self.on_election_complete()

        


    def record_view_change_message(self, view: int, msg: dict):
        """Store a view-change message for the given view."""
        if view not in self.view_change_messages:
            self.view_change_messages[view] = []
        if view not in self.view_change_messages_w_invalids:
            self.view_change_messages_w_invalids[view] = []

        sender = msg.get("sender")
        if sender and all(m.get("sender") != sender for m in self.view_change_messages[view]):
            self.view_change_messages[view].append(msg)
            self.view_change_messages_w_invalids[view].append(msg)
            # print(f"[Node {self.node_id}] Recorded view-change from {sender} for view {view}")


    def has_view_change_quorum(self, view: int) -> bool:
        """Return True if we have 2f+1 view-change messages for this view."""
        # print(f"[Node {self.node_id}] Checking view-change quorum for view {view}: {len(self.view_change_messages.get(view, []))} messages")
        return len(self.view_change_messages.get(view, [])) >= 2 * self.f + 1
    

    async def handle_new_view(self, msg: dict):
        view = msg.get("view")
        V = msg.get("V", [])
        O = msg.get("O", [])

        #if not self.validate_new_view(V, O):
        #    print(f"[Node {self.node_id}] Invalid NEW-VIEW for view {view}")
        #    return

        self.current_view = view
        self.role = "BACKUP"
        self.in_view_change = False

        # Add pre-prepares in O to log
        for pp_msg in O:
            self.pre_prepared_messages[(view, pp_msg["seq"])] = pp_msg
            self.requests_in_processing[(view, pp_msg["seq"], pp_msg["digest"])] = pp_msg["request"]

        # clear requests in processing for prior view
        keys_to_remove = [key for key in self.requests_in_processing if key[0] < view]
        for key in keys_to_remove:
            self.requests_in_processing.pop(key, None)


        # Fire-and-forget PREPARE for each message
        for pp_msg in O:

            prepare_msg = {
                "type": "PREPARE",
                "view": view,
                "seq": pp_msg["seq"],
                "digest": pp_msg["digest"],
                "sender": self.node_id
            }

            # send to leader
            if self.attack is not None and self.attack.get("dark", False) and self.is_byzantine and msg["sender"] in self.attack.get("dark_set", set()):
                await self.print_to_log(prepare_msg)
            asyncio.create_task(self.safe_send(msg["sender"], deepcopy(prepare_msg)))

        # print(f"[Node {self.node_id}] Entered view {view}, sent PREPARE for O messages")


    def compute_min_max_seq(self, V: list[dict]) -> tuple[int, int]:
        """
        Compute min and max sequence numbers for NEW-VIEW construction.
        
        :param V: list of view-change messages
        :return: (min_s, max_s)
            - min_s: sequence number of the latest stable checkpoint
            - max_s: highest sequence number in any prepare set
        """
        min_s = 0
        max_s = 0

        # Find the latest stable checkpoint across all VIEW-CHANGE messages
        # print("Computing min/max seq from V:", V)
        for vc_msg in V:
            checkpoints = vc_msg.get("C", [])
            for cp in checkpoints:
                cp_seq = cp.get("seq", 0)
                if cp_seq > min_s:
                    min_s = cp_seq

        # rint("Computed min_s:", min_s)
        # Find the highest prepared sequence number
        for vc_msg in V:
            for (seq_num, preprepare_msg, prepares) in vc_msg.get("P", []):
                if seq_num > max_s:
                    max_s = seq_num
        # print("Computed max_s:", max_s)
        return min_s, max_s
    

    def create_null_preprepare(self, seq_num: int, view: int) -> dict:
        """
        Creates a null pre-prepare message for a given sequence number and view.
        This message represents a no-op request with digest `dnull`.
        """
        # You can define a standard null request digest (just a placeholder)
        dnull = "NULL_DIGEST"

        preprepare_msg = {
            "type": "PRE-PREPARE",
            "view": view,
            "seq": seq_num,
            "digest": dnull,
            "request": None,   # no actual client request
            "sender": self.node_id
        }

        # Sign the message before returning
        msg_copy, msg_bytes = self._prepare_message_bytes(preprepare_msg)
        msg_signed = self._attach_signature(msg_copy, msg_bytes)
        return msg_signed
    
    def on_election_complete(self):
        """
        Called when the election is complete
        """
        self.in_view_change = False
        while self.queued_requests:
            req = self.queued_requests.pop(0)
            if req not in self.requests_in_processing.values() and tuple(req) not in self.executed_requests:
                # print(f"[Node {self.node_id}] Processing queued request after election: {req}")
                asyncio.create_task(self.process_pending_request(req)) 
    

# ========================== Handle Client Request =========================




    async def handle_client_request(self, msg: dict, client_websocket):
        """
       Node Handles a client REQUEST message.
        """

        txn = msg.get("txn")
        if not txn:
            # print(f"[Node {self.node_id}] Malformed REQUEST message: {msg}")
            return

        # print(f"[Node {self.node_id}] Handling client request: {txn}")
        self.queued_requests.append(txn + [msg.get("timestamp", 0)]) # sender, receiver, amount, timestamp

        if self.in_view_change:
            # print(f"[Node {self.node_id}] Currently in view change, cannot process request yet.")
            return
        
        
        # not in VC continue handling req
        if self.role != "LEADER":
            # print(f"[Node {self.node_id}] I am a BACKUP, forwarding request to LEADER.")
            # Forward to leader
            leader_id = self.current_view % len(self.other_nodes)
            if leader_id == 0:
                leader_id = len(self.other_nodes)

            await self.print_to_log(msg)
            asyncio.create_task(self.safe_send(leader_id, msg, forwarded_req = True)) 
        else:
            
            # print(f"[Node {self.node_id}] I am the LEADER, processing request.")

            # move from queueed to processing
            txn_to_process = self.queued_requests.pop(0)
            
            asyncio.create_task(self.process_pending_request(txn_to_process))


    async def process_pending_request(self, txn: list) -> bool:
        """Handle the processing of an in progress client request"""
        

        # TODO move ending logic from previous function here

        seq_num = self.last_assigned_seq + 1

        txn_bytes = json.dumps(txn, sort_keys=True).encode()
        digest = hashlib.sha256(txn_bytes).hexdigest()

        # check for no duplicates
        txn_key = tuple(txn)  
        if txn_key in self.requests_in_processing.values() or tuple(txn_key) in self.executed_requests.values():
            # print(f"[Node {self.node_id}] Duplicate request detected, ignoring: {txn}")
            return
        else:
            pass
            # print(f"[Node {self.node_id}] txn_key: {txn_key} ")
            # print(f"[Node {self.node_id}] requests_in_processing: {self.requests_in_processing} ")
        
        if self.last_reply_per_client.get(txn[0]) == txn:
            # print(f"[Node {self.node_id}] Duplicate request from client {txn[0]}, ignoring: {txn}")
            return
        
        # assign seqnum
        
        
        if self.attack is not None and self.attack.get("equivocation") and self.is_byzantine:
            self.last_assigned_seq = seq_num + 1
        else:
            self.last_assigned_seq = seq_num

        # print(f"[Node {self.node_id}] Processing request: {txn}, assigning seq number: {self.last_assigned_seq}")



        self.requests_in_processing[(self.current_view, seq_num, digest)] = txn_key


        # Create PRE-PREPARE message
        msg = {
            "type": "PRE-PREPARE",
            "view": self.current_view,
            "seq": seq_num,
            "digest": digest,
            "sender": self.node_id,
            "request": txn,
        }
        msg_higer_seq = deepcopy(msg)
        msg_higer_seq["seq"] = seq_num + 1


        # 6 Broadcast PRE-PREPARE to all backups (fire-and-forget)
        for node_id in self.other_nodes:
            if node_id == self.node_id:
                await self.print_to_log(msg)
                if self.attack is not None and self.attack.get("equivocation") and self.is_byzantine:
                    await self.print_to_log(msg_higer_seq)
                continue
            asyncio.create_task(self.safe_send(node_id, deepcopy(msg)))

        # print(f"[Node {self.node_id}] Sent PRE-PREPARE (seq={seq_num}, digest={digest[:10]}...) to all replicas")


        if self.attack is not None and self.attack.get("equivocation") and self.is_byzantine:
            self.pre_prepared_messages[(self.current_view, seq_num + 1)] = msg
            self.pre_prepared_messages[(self.current_view, seq_num)] = msg
        else:
            self.pre_prepared_messages[(self.current_view, seq_num)] = msg

        return True


    def primary_id_for_view(self, view: int) -> int:
        """ Helper to get primary node id for a given view """
        n = len(self.other_nodes)
        primary = view % n
        if primary == 0:
            primary = n
        return primary

    async def handle_preprepare(self, msg):
        view = msg["view"]
        seq = msg["seq"]
        digest = msg["digest"]
        leader_id = msg["sender"]

        if view != self.current_view:
            # print(f"[Node {self.node_id}] Ignoring PRE-PREPARE for old view {view}")
            return

        if leader_id != self.primary_id_for_view(self.current_view):
            # print(f"[Node {self.node_id}] PRE-PREPARE from non-leader {leader_id} for view {view}")
            # print(f"[Node {self.node_id}] Invalid PRE-PREPARE sender {leader_id}")
            return
        
        # starts if not already running 
        self.start_view_timer()

        request = msg.get("request")
        if request:
            txn_bytes = json.dumps(request, sort_keys=True).encode()
            local_digest = hashlib.sha256(txn_bytes).hexdigest()
            if local_digest != digest:
                # print(f"[Node {self.node_id}] Digest mismatch! Possible Byzantine leader.")
                return

        if (view, seq) in self.pre_prepared_messages:
            if self.pre_prepared_messages[(view, seq)]["digest"] != msg["digest"]:
                # print(f"[Node {self.node_id}] Conflicting PRE-PREPARE for seq={seq}, view={view}")
                # print("digest 1:", self.pre_prepared_messages[(view, seq)]["digest"])
                # print("digest 2:", digest)
                return
        self.pre_prepared_messages[(view, seq)] = msg
        # print(f"[Node {self.node_id}] PRE-PREPARE accepted for seq={seq}, digest={digest[:10]}...")

        
        self.requests_in_processing[(view, seq, digest)] = tuple(request)

        # TODO
        if self.attack is not None and self.attack.get("crash", False) and self.is_byzantine:
            # print(f"[Node {self.node_id}] Simulating crash after PRE-PREPARE.")
            return
        
        # fire-and-forget send PREPARE
        prepare_msg = {
            "type": "PREPARE",
            "view": view,
            "seq": seq,
            "digest": digest,
            "sender": self.node_id
        }

        # send only to leader
        if self.attack is not None and self.attack.get("dark", False) and self.is_byzantine and msg["sender"] in self.attack.get("dark_set", set()):
            await self.print_to_log(prepare_msg)
        asyncio.create_task(self.safe_send(leader_id, prepare_msg))
        # print(f"[Node {self.node_id}] Sent PREPARE(seq={seq}) to leader {leader_id}")


    async def handle_prepare(self, msg: dict):
        """
        Leader-side handler for PREPARE messages in Linear-PBFT.

        Backup replicas send PREPARE only to the leader (collector).
        Leader collects them and once quorum ≥ n - f is reached,
        it broadcasts a PREPARE-BROADCAST bundle to all replicas.
        """
        view = msg["view"]
        seq = msg["seq"]
        digest = msg["digest"]
        sender = msg["sender"]

        # Only leader collects PREPARE messages
        if self.node_id != self.primary_id_for_view(view):
            # rint(f"[Node {self.node_id}] Ignoring PREPARE (not leader)")
            return

        # Ignore messages for old views
        if view != self.current_view:
            # print(f"[Node {self.node_id}] PREPARE for wrong view {view}")
            return

        key = (view, seq, digest)

        # Store signed prepare messages keyed by tuple
        if key not in self.prepare_certificates:
            self.prepare_certificates[key] = {}
            self.prepare_timer_active[key] = True
            self.prepare_timer_tasks[key] = asyncio.create_task(
                self._prepare_collection_timer(key, timeout_secs=0.5)
            )

        prepares = self.prepare_certificates[key]

        # Keep only one PREPARE per sender
        if sender in prepares:
            # print(f"[Node {self.node_id}] Duplicate PREPARE from {sender} ignored")
            return

        # Save the signed prepare message
        prepares[sender] = msg

        # print(f"[Node {self.node_id}] Collected {len(prepares)} / {self.f*2} PREPAREs for seq={seq}")

        if key in self.sent_prepare_certs:
            # print(f"[Node {self.node_id}] Already broadcasted PREPARE-BROADCAST for seq={seq}, ignoring")
            return # Already broadcasted
        
        if len(prepares) == 3*self.f:
            # Cancel timer if running
            if self.prepare_timer_active.get(key):
                self.prepare_timer_active[key] = False
                self.prepare_timer_tasks[key].cancel()
                del self.prepare_timer_tasks[key]
                # print(f"[Node {self.node_id}] Prepare collection timer cancelled for seq={seq}")

            await self._send_prepare_broadcast(view, seq, digest, optimistic_reduction=True)
                    


    async def _send_prepare_broadcast(self, view: int, seq: int, digest: str, optimistic_reduction: bool = False):


        # Acquire lock for this key to prevent race-condition in broadcasting
        key = (view, seq, digest)
        async with self.prepare_locks[key]:
            # Already broadcast?
            if key in self.sent_prepare_certs:
                return

            key = (view, seq, digest)
            # print(f"[Node {self.node_id}] Quorum reached for PREPARE (seq={seq}), broadcasting PREPARE-BROADCAST")


            # Also mark as committed locally since leader participates
            self_commit_msg = {
                "type": "COMMIT",
                "view": view,
                "seq": seq,
                "digest": digest,
                "sender": self.node_id
            }
            # print(f"[node {self.node_id}] after attach in prep b - seq={seq}")
            partially_signed = self._attach_signature(self_commit_msg, self.canonical_json_bytes(self_commit_msg))

            self.commit_certificates[key] = {self.node_id: partially_signed}
            

            # print(f"[node {self.node_id}] after attach in prep b - seq={seq}")

            bundle_msg = {
                "type": "PREPARE-BROADCAST" if not optimistic_reduction else "PREPARE-BROADCAST-OPT",
                "view": view,
                "seq": seq,
                "digest": digest,
                "sender": self.node_id
            }

            if not (self.attack is not None and self.attack.get("crash") and self.is_byzantine):
                self.prepared_messages[key] = bundle_msg  # self record as prepared TODO do i need this?
            else:
                return

            # Broadcast to ALL replicas (excluding self if desired)
            for node_id in self.other_nodes:
                if node_id == self.node_id:
                    await self.print_to_log(bundle_msg)
                    continue

                    
                else:
                    # print("sending prepare broadcast to ", node_id, " for seq=", seq)
                    asyncio.create_task(
                        self.safe_send(node_id, deepcopy(bundle_msg))
                    )


            # Mark broadcast done so we don't resend
            self.sent_prepare_certs[key] = True

            if optimistic_reduction:
                # print(f"[Leader {self.node_id}] Using optimistic commit reduction for seq={seq}")
                self.committed_entries.add(key)

                await self.sequentially_execute_committed(key, phase_reduction=True)



    async def _prepare_collection_timer(self, key, timeout_secs: float):
        """Runs after first PREPARE to monitor prepare collection."""
        try:
            await asyncio.sleep(timeout_secs)
        except asyncio.CancelledError:
            # Timer was cancelled early due to enough PREPAREs
            # print(f"[Leader {self.node_id}] Timer cancelled cleanly before timeout")
            return

        count = len(self.prepare_certificates.get(key, {}))
        if count == {}:
            print("Problem here")

        # print(f"[Leader {self.node_id}] Timer expired after {timeout_secs}s with {count} prepares")

        if count >= 3 * self.f:
            await self._send_prepare_broadcast(key[0], key[1], key[2], optimistic_reduction=True)

        elif count >= len(self.other_nodes) - self.f - 1:
            await self._send_prepare_broadcast(key[0], key[1], key[2])

        else:
            # print(f"[Leader {self.node_id}] Fewer than n-f prepares ({count}/{self.n - self.f}); waiting...")
            # Wait asynchronously for threshold
            await self._wait_for_minimum_prepares(key)

    async def _wait_for_minimum_prepares(self, key):
        """Wait until n-f prepares are received, then continue normal routine."""

        # print(f"[Leader {self.node_id}] Waiting for n-f prepares to proceed...")
        while len(self.prepare_certificates.get(key, {})) < len(self.other_nodes) - self.f:
            await asyncio.sleep(0.1)  # periodic check

        # print(f"[Leader {self.node_id}] Now reached n-f prepares, continuing normal routine")
        await self._continue_normal_commit()


    async def handle_prepare_broadcast(self, msg: dict, optimized: bool = False):
        """
        Backup-side handler for PREPARE-BROADCAST messages (Prepare-Certificate)
        from the leader in Linear-PBFT.

        A backup only sends COMMIT if:
        It is in the correct view
        It has received the corresponding PRE-PREPARE earlier
        The broadcast contains a quorum of signed PREPARE messages
        """

        view = msg["view"]
        seq = msg["seq"]
        digest = msg["digest"]
        sender = msg["sender"]
        prepares = msg.get("prepares", [])

        # Only backups process prepare-cert
        if self.node_id == self.primary_id_for_view(view):
            # print(f"[Node {self.node_id}] Ignoring PREPARE-BROADCAST (leader)")
            return

        # Ignore wrong view
        if view != self.current_view:
            # print(f"[Node {self.node_id}] PREPARE-BROADCAST for wrong view {view}, expected {self.current_view}")
            return

        key = (view, seq, digest)

        # Safety check: ensure we validated matching PRE-PREPARE earlier
        if (view, seq) not in self.pre_prepared_messages or \
        self.pre_prepared_messages[(view, seq)]["digest"] != digest:
            # print(f"[Node {self.node_id}]  Cannot be considerred prepared seq={seq}: PRE-PREPARE missing/mismatch")
            # print("Expected digest:", self.pre_prepared_messages.get((view, seq), {}).get("digest"))
            # print("REJECTING prepare-broadcast and not sending out commit here")
            return
        
        if self.attack is not None and self.attack.get("crash", False) and self.is_byzantine:
            # print(f"[Node {self.node_id}] Byzantine crash for seq={seq}. Do not set status to prepared")
            return
        else:
            self.prepared_messages[(view, seq, digest)] = msg

        total_replicas = len(self.other_nodes)
        f = (total_replicas - 1) // 3
        quorum_needed = total_replicas - f  # n - f

        #print(f"[Node {self.node_id}] Got PREPARE-BROADCAST with {len(prepares)} prepares "
        #    f"(need {quorum_needed}) for seq={seq}")

        # Only send COMMIT once per (view, seq, digest)
        if key in self.sent_commits:
            # print(f"[Node {self.node_id}] Already sent COMMIT for seq={seq}")
            return


        # print(f"[Node {self.node_id}] Prepared for seq={seq}, sending COMMIT")

        if not optimized:
            commit_msg = {
                "type": "COMMIT",
                "view": view,
                "seq": seq,
                "digest": digest,
                "sender": self.node_id
            }
            if self.attack is not None and self.attack.get("dark", False) and self.is_byzantine and msg["sender"] in self.attack.get("dark_set", set()):
                await self.print_to_log(commit_msg)
            # Fire-and-forget async commit send back to leader
            asyncio.create_task(self.safe_send(sender, commit_msg))

            self.sent_commits[key] = True  # Mark as sent

        else:
            # print(f"[Node {self.node_id}] Using optimistic commit reduction, skipping COMMIT send for seq={seq}")
            self.committed_entries.add(key)

            # backups directly commit the request
            self.committed_entries.add((msg["view"], msg["seq"], msg["digest"]))

            # Execute the committed transaction
            await self.sequentially_execute_committed((msg["view"], msg["seq"], msg["digest"]))


    async def handle_commit(self, msg: dict):
        """
        Leader-side handler for COMMIT messages in Linear-PBFT.

        Replicas send COMMIT only to the leader once they see a valid PREPARE-BROADCAST.
        The leader collects COMMIT messages and once quorum ≥ n - f is reached,
        it broadcasts a COMMIT-BROADCAST to finalize the decision.
        """
        view = msg["view"]
        seq = msg["seq"]
        digest = msg["digest"]
        sender = msg["sender"]

        # Only leader processes COMMIT messages
        if self.node_id != self.primary_id_for_view(view):
            # print(f"[Node {self.node_id}] Ignoring COMMIT (not leader)")
            return

        # Ignore OLD views
        if view != self.current_view:
            # print(f"[Node {self.node_id}] COMMIT for wrong view {view}")
            return

        key = (view, seq, digest)

        # verify partial signature so that only legit ones are included in the braodcast
        if not self.verify_signature(msg, sender):
            # print(f"[Node {self.node_id}] Invalid signature on COMMIT from {sender}")
            return

        # Initialize commit certificate storage for this key
        if key not in self.commit_certificates:
            self.commit_certificates[key] = {}

        commits = self.commit_certificates[key]

        # Deduplicate commit from same sender
        if sender in commits:
            # print(f"[Node {self.node_id}] Duplicate COMMIT from {sender} ignored")
            return

        # Store the signed commit message
        commits[sender] = msg

        total_replicas = len(self.other_nodes)
        f = (total_replicas) // 3
        quorum_needed = total_replicas - f

        # print(f"[Node {self.node_id}] Collected {len(commits)} / {quorum_needed} COMMITS for seq={seq}")

        # Lock to prevent concurrent broadcast attempts
        async with self.commit_locks[key]:

            # If already finalized, skip
            if key in self.sent_commit_certs:
                return

            # Quorum reached → decide the operation
            if len(commits) >= quorum_needed:
                # print(f"[Node {self.node_id}] Quorum reached for COMMIT (seq={seq}), broadcasting COMMIT-BROADCAST")

                bundle_msg = {
                    "type": "COMMIT-BROADCAST",
                    "view": view,
                    "seq": seq,
                    "digest": digest,
                    "sender": self.node_id
                    #"commits": list(commits.values())
                }

                # mark as committed
                self.committed_entries.add(key)

                # Broadcast commits to all replicas (can exclude self if desired)
                for node_id in self.other_nodes:
                    if node_id != self.node_id:
                        asyncio.create_task(self.safe_send(node_id, deepcopy(bundle_msg)))
                    else:
                        await self.print_to_log(bundle_msg)

                # Mark broadcast as done
                self.sent_commit_certs[key] = True

                # Leader executes immediately upon finalization
                await self.sequentially_execute_committed(key)


    async def handle_commit_broadcast(self, msg: dict):
        """
        Backup-side handler for COMMIT-BROADCAST messages from the leader.

        In Linear-PBFT, backups do NOT verify quorum again.
        The leader ensures quorum and includes the commit certificate.
        Backups only:
        - store commit certificate
        - trigger sequential execution if the seq is next in order
        """

        view = msg["view"]
        seq = msg["seq"]
        digest = msg["digest"]
        commits = msg.get("commits", [])

        # Only backups process this
        if self.node_id == self.primary_id_for_view(view):
            # print(f"[Node {self.node_id}] Ignoring COMMIT-BROADCAST (leader)")
            return

        # Wrong view?
        if view != self.current_view:
            # print(f"[Node {self.node_id}] COMMIT-BROADCAST for wrong view {view}, expected {self.current_view}")
            return

        # Safety check: ensure we validated matching PRE-PREPARE earlier
        if (view, seq) not in self.pre_prepared_messages or \
        self.pre_prepared_messages[(view, seq)]["digest"] != digest or \
            (view, seq, digest) not in self.prepared_messages:
            # print(f"[Node {self.node_id}] Cannot be considered committed - seq={seq}: PRE-PREPARE missing/mismatch or prepare missing/mismatch")
            return


        key = (view, seq, digest)

        # Dedup: already executed?
        if key in self.executed_requests:
            # print(f"[Node {self.node_id}] Already executed seq {key}, ignoring commit broadcast")
            return


        # add to committed
        self.committed_entries.add(key)

        # print(f"[Node {self.node_id}] Commit certificate installed for key {key}, attempting execution")

        # Attempt sequential execution
        await self.sequentially_execute_committed(key)

    async def sequentially_execute_committed(self, committed_key: tuple, phase_reduction: bool = False):
        """
        Sequentially execute committed transactions starting from the last executed sequence.
        This can be called by both leader and backup nodes after a new COMMIT or COMMIT-BROADCAST.

        committed_key: tuple (view, seq, digest) that was just committed.
        """

        # print(f"[Node {self.node_id}] Attempting sequential execution starting from committed key: {committed_key}")
        view, seq, digest = committed_key
        next_seq = self.last_executed_seq + 1

        # Skip if the committed transaction is already executed
        if seq <= self.last_executed_seq:
            return

        while True:
            # Find the committed transaction for the next sequence number
            key_to_execute = None

            if not phase_reduction:
                for (v, s, d) in self.committed_entries:
                    if s == next_seq and view == v:
                        key_to_execute = (v, s, d)
                        # print(f"[Node {self.node_id}] Found committed transaction for view={v} seq={s}: {key_to_execute}")
                        break
            else:
                for (v, s, d) in self.prepared_messages.keys():
                    if s == next_seq and view == v:
                        key_to_execute = (v, s, d)
                        # print(f"[Node {self.node_id}] Found committed transaction for view={v} seq={s}: {key_to_execute}")
                        break

            if not key_to_execute:
                # No committed transaction yet for next_seq → stop
                # print(f"[Node {self.node_id}] leaving sequentially at seq {next_seq}, no committed txn found")
                # print("prepared entries: ", self.prepared_messages.keys())
                break


            # print(f"[Node {self.node_id}] Executing seq={next_seq} (view={key_to_execute[0]})")
            assert key_to_execute[1] == next_seq
            if key_to_execute[1] not in self.executed_requests:
                await self.execute(key_to_execute)
            next_seq += 1
            
        # print(f"[Node {self.node_id}] Finished sequential execution up to seq {self.last_executed_seq}")



    async def execute(self, key_to_execute: tuple):
        """
        Execute the committed transaction with the given sequence number and digest.
        Sends replies to clients as needed.
        """
        view, seq, digest = key_to_execute
        # print(f"[Node {self.node_id}] Executing transaction (view={view}, seq={seq}, digest={digest})")

        # Retrieve the transaction data (digest -> transaction)
        transaction = self.requests_in_processing.get((view, seq, digest))
        if transaction is None:
            # print(f"[Node {self.node_id}] Transaction not found for digest={digest}, skipping execution")
            # print("transaction: " , transaction)
            # print("requests in processing: ", self.requests_in_processing)
            # print("key to execute: ", key_to_execute)
            pass


        # print(f"[Node {self.node_id}] Retrieved transaction for execution: {transaction}, key: {key_to_execute}")
        self.executed_requests[seq] = transaction

        sender = -1 if digest == "NULL_DIGEST" else transaction[0]
        tx_status = ""
        if digest!= "NULL_DIGEST" and len(transaction) >= 3: # reg txn
            
            receiver = transaction[1]
            amount = transaction[2]

            
            # Check if transaction can be executed
            if self.balances[sender] >= amount:
                # Execute transaction
                self.balances[sender] -= amount
                self.balances[receiver] += amount
                self.save_to_persistent(self.balances)
                tx_status = "ok"
                # print(f"[Node {self.node_id}] Executed tx: {sender}->{receiver} {amount}. Balances: {self.balances}")
            else:
                # Cannot execute transaction: insufficient funds
                tx_status = "failed"
                # print(f"[Node {self.node_id}] Transaction failed: {sender} has insufficient balance ({self.balances[sender]}), tx skipped.")

        else:
            tx_status = "ok"
            # print(f"[Node {self.node_id}] executing read only txn: {transaction}")

        self.last_executed_seq = seq

        # remove from in processing
        del self.requests_in_processing[(view, seq, digest)]

        # reset view timer if there are pending reqs or stop if not
        self.reset_view_timer_if_pending()


        # record last reply per client
        if digest != "NULL_DIGEST":
            self.last_reply_per_client[sender] = transaction

            # Send reply to client
            reply_msg = {
                "type": "REPLY",
                "seq": seq,
                "digest": digest,
                "status": tx_status,
                "timestamp": transaction[1] if len(transaction) == 2 else transaction[3],
                "sender": self.node_id,
                "read_only": len(transaction) == 2,
                "leader": self.role == "LEADER"
            }
            
            # Fire-and-forget send reply
            await self.print_to_log(reply_msg)
            asyncio.create_task(self.send_reply_to_client(sender, reply_msg))

        # check if a checkpoint is needed
        if seq % self.checkpoint_interval == 0:

            # print(f"[Node {self.node_id}] creating checkpoint, just executed seq {seq}")
            await self.create_checkpoint(seq)



    async def create_checkpoint(self, seq: int):
        """
        Create a checkpoint for the given sequence number.
        """
        # print(f"[Node {self.node_id}] Creating checkpoint at seq {seq}")
        
        checkpoint_msg = {
            "type": "CHECKPOINT",
            "seq": seq,
            "digest": hashlib.sha256(json.dumps(self.balances, sort_keys=True).encode()).hexdigest(),
            "sender": self.node_id,
            "state": deepcopy(self.balances)
        }

        
        if seq not in self.checkpoints_received:
            self.checkpoints_received[seq] = []
        
        self.checkpoints_received[seq].append(checkpoint_msg)

        # Fire-and-forget send checkpoint to all replicas
        for node_id in self.other_nodes:
            if node_id == self.node_id:
                await self.print_to_log(checkpoint_msg)
                continue
            asyncio.create_task(self.safe_send(node_id, deepcopy(checkpoint_msg)))


    async def handle_checkpoint(self, msg: dict):
        """
        Handle incoming CHECKPOINT message from another replica.
        """

        # print(f"[Node {self.node_id}] received checkpoint message")
        seq = msg.get("seq")
        digest = msg.get("digest")
        sender = msg.get("sender")
        state = msg.get("state")

        if seq is None or digest is None or sender is None:
            print(f"[Node {self.node_id}] Malformed CHECKPOINT message: {msg}")
            return

        

        if seq not in self.checkpoints_received:
            self.checkpoints_received[seq] = []

        # Deduplicate checkpoint from same sender
        if sender in self.checkpoints_received[seq]:
            # print(f"[Node {self.node_id}] Duplicate CHECKPOINT from {sender} ignored")
            return

        self.checkpoints_received[seq].append(msg)

        quorum_needed = 2 * self.f + 1

        # print(f"[Node {self.node_id}] Collected {len(self.checkpoints_received[seq])} / {quorum_needed} CHECKPOINTs for seq={seq}")

        if len(self.checkpoints_received[seq]) >= quorum_needed and seq not in self.stable_checkpoints:
            # print(f"[Node {self.node_id}] Checkpoint quorum reached for seq={seq}, installing checkpoint")
            

            if self.last_executed_seq < seq:
                # print(f"[Node {self.node_id}] Warning: Checkpoint seq {seq} is higher than last executed seq {self.last_executed_seq} - restoring state")
                self.balances = deepcopy(state)

                # clear logs up to seq
                self.last_executed_seq = seq
                self.last_assigned_seq = max(self.last_assigned_seq, seq)
            

            self.stable_checkpoints.append(seq)


    async def handle_read_only_request(self, msg: dict):

        if tuple(msg["txn"]) in self.executed_readonly_non_seqs:
            # print(f"[Node {self.node_id}] Duplicate READ-ONLY request from client {msg['txn'][0]}, ignoring: {msg}")
            return

        client = msg.get("txn")[0]
        read_val = self.balances.get(client, None)
        reply_msg = {
            "type": "READ-ONLY-REPLY",
            "view": self.current_view,
            "timestamp": msg.get("timestamp", 0),
            "client": client,
            "sender": self.node_id,
            "r": read_val,
            "leader": self.role == "LEADER"
        }
        
        self.executed_readonly_non_seqs.add(tuple(msg["txn"]))
        
        if self.attack is not None and self.attack.get("crash") and self.is_byzantine:
            return
        
        # Fire-and-forget send reply
        await self.print_to_log(reply_msg)
        asyncio.create_task(self.send_reply_to_client(client, reply_msg))

    async def handle_cancel(self, msg: dict):
        """
        Handle CANCEL message from main - kill all timers and pending requests.
        """

        # print(f"[Node {self.node_id}] Handling CANCEL - stopping all timers and clearing pending requests.")

        # Cancel view change timer
        if self.current_view_timer is not None:
            self.current_view_timer.cancel()

        # Cancel prepare timers
        for key, task in self.prepare_timer_tasks.items():
            task.cancel()
        self.prepare_timer_tasks.clear()
        self.prepare_timer_active.clear()


        # Clear pending requests
        self.queued_requests.clear()
        self.requests_in_processing.clear()

        # print(f"[Node {self.node_id}] CANCEL complete.")


# ================================ PRINT FUNCTIONS ================================

    async def handle_status_request(self, msg: dict):
        """
        Handle STATUS-REQUEST message from a client.
        """

        # print(f"[Node {self.node_id}] Handling STATUS-REQUEST: {msg['arg1']}")
        
        if msg["arg1"] == "printlog":
            return {"response": self.log}

        elif msg["arg1"] == "printdb":
            return {"response": self.balances}

        elif msg["arg1"] == "printstatus":
            seq = int(msg["arg2"])
            response = "X"
            if seq in self.executed_requests:
                response = "E"
            elif any(r[1] == seq for r in self.committed_entries):
                response = "C"
            elif any(r[1] == seq for r in self.prepared_messages):
                response = "P"
            elif any(r[1] == seq for r in self.pre_prepared_messages):
                response = "PP"

            return {"response": response}

        elif msg["arg1"] == "printview":
            response = self.new_view_log
            return {"response": response}

        elif msg["arg1"] == "benchmark":
            response = await self.benchmark_task

            return {"response": response}

        else:
            print(f"[Node {self.node_id}] Unknown STATUS-REQUEST type: {msg['arg1']}")
            return
        

    async def run_node_benchmark(self, interval=0.05):
        """
        Asynchronously samples CPU, memory, and network usage while self.benchmark_active is True.
        Returns statistics including average and max values, with units in % for CPU, MB for memory,
        and MB/s for network throughput. The dictionary is flattened for easy logging.
        """
        pid = os.getpid()
        process = psutil.Process(pid)

        cpu_samples = []
        rss_samples = []
        vms_samples = []
        net_samples = []

        # Initialize CPU percent
        process.cpu_percent(interval=None)
        net_io_prev = psutil.net_io_counters()

        while self.benchmark_active:
            # CPU percent since last call
            cpu_samples.append(process.cpu_percent(interval=None))

            # Memory usage
            mem_info = process.memory_info()
            rss_samples.append(mem_info.rss / (1024 * 1024))  # MB

            # Network usage
            net_io_current = psutil.net_io_counters()
            bytes_sent = net_io_current.bytes_sent - net_io_prev.bytes_sent
            bytes_recv = net_io_current.bytes_recv - net_io_prev.bytes_recv
            net_samples.append((bytes_sent + bytes_recv) / interval / (1024 * 1024))  # MB/s
            net_io_prev = net_io_current

            await asyncio.sleep(interval)

        # Compute statistics
        def stats(samples):
            if not samples:
                return 0, 0
            return sum(samples) / len(samples), max(samples)

        cpu_avg, cpu_max = stats(cpu_samples)
        rss_avg, rss_max = stats(rss_samples)
        net_avg, net_max = stats(net_samples)

        results = {
            "cpu_percent_avg": round(cpu_avg, 2),        # %
            "cpu_percent_max": round(cpu_max, 2),        # %
            "memory_rss_mb_avg": round(rss_avg, 2),      # MB
            "memory_rss_mb_max": round(rss_max, 2),      # MB
            "network_mb_s_avg": round(net_avg, 2),       # MB/s
            "network_mb_s_max": round(net_max, 2),       # MB/s
        }

        return results


            