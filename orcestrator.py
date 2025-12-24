# file written with GPT
import csv
import multiprocessing
import sys
import re
from time import time
from typing import List, Set, Dict, Any
import asyncio
import json
from collections import deque
from node import Node
from client import Client
import threading
import subprocess
import time
import psutil
from collections import deque
import select
import socket
import websockets
import os


import config

clients = {chr(ord('A') + i): Client(chr(ord('A') + i), config.nodes_info, 6001 + i, config.client_keys[chr(ord('A') + i)], config.all_public_keys) for i in range(config.NUM_CLIENTS)}
throughput = -1
persistent_connections = {}



def parse_node_list(node_list_str):
    """
    Converts a string like "[n1, n2, n3]" into a set of integers {1, 2, 3}.
    Returns an empty set if the input is empty or invalid.
    """
    if not node_list_str or node_list_str.strip() == "":
        return set()
    # Extract all numbers following 'n'
    nodes = re.findall(r"n(\d+)", node_list_str)
    return {int(n) for n in nodes}


def parse_transaction(txn_str: str):
    """
    Converts a transaction string like "(A, C, 1)" into a tuple:
        ('A', 'C', 1)
    Handles:
        - Letters as strings
        - Numbers as ints
        - Single element like "(G)" -> ('G',)
    """
    if txn_str.strip() == "LF":
        return "LF"

    if not txn_str:
        return ()
    s = txn_str.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    if not s:
        return ()
    
    elements = []
    for part in s.split(","):
        part = part.strip()
        if part.isdigit():
            elements.append(int(part))
        else:
            elements.append(part)
    return tuple(elements)


def parse_attacks(attack_str: str) -> Dict[str, Any]:
    """
    Parse an attack string into a dictionary:
      {
        "crash": bool,
        "sign": bool,
        "dark": set[int],
        "time": bool,
        "equivocation": set[int]
      }
    """
    attacks = {
        "crash": False,
        "sign": False,
        "dark": False,
        "time": False,
        "equivocation": False,
        "dark_set": set(),
        "equivocation_set": set()
    }

    if not attack_str or attack_str.strip() in ("", "[]"):
        return attacks

    s = attack_str.strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1].strip()
    elif s.startswith('"') and s.endswith('"'):
        s = s[2:-2].strip()
    if s == "":
        return attacks

    raw_parts = [p.strip() for p in re.split(r";", s) if p.strip()]
    tokens = []
    for part in raw_parts:
        if "(" in part and ")" in part:
            tokens.append(part)
        else:
            for tok in part.split(","):
                tok = tok.strip()
                if tok:
                    tokens.append(tok)

    def nodes_from_paren(text: str) -> Set[int]:
        return {int(m) for m in re.findall(r"n(\d+)", text)}

    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue
        m = re.match(r"^([A-Za-z_]+)\s*(\((.*)\))?$", tok)
        if not m:
            continue
        name = m.group(1).lower()
        paren_content = m.group(3)

        if name == "crash":
            attacks["crash"] = True
        elif name == "sign":
            attacks["sign"] = True
        elif name == "dark" and paren_content:
            attacks["dark"] = True
            attacks["dark_set"].update(nodes_from_paren(paren_content))
        elif name == "time":
            attacks["time"] = True
        elif name == "equivocation" and paren_content:
            attacks["equivocation"] = True
            attacks["equivocation_set"].update(nodes_from_paren(paren_content))

    #    print("token parsed:", tok)
    #print("attacks after parsing token:", attacks)
    return attacks


def read_test_file(filename: str):
    """
    Reads the test CSV and returns a list of test_set dicts:
      { "set_number": int,
        "transactions": [tuple, ...],
        "live": set[int],
        "byzantine": set[int],
        "attacks": { ...as parse_attacks returns... }
      }
    """
    test_sets = []
    current_set = None

    with open(filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # skip header

        for row in reader:
            if not any(cell.strip() for cell in row if cell is not None):
                continue

            set_num = row[0].strip() if len(row) > 0 and row[0] else ""
            txn = row[1].strip() if len(row) > 1 and row[1] else None
            live_col = row[2].strip() if len(row) > 2 and row[2] else ""
            byz_col = row[3].strip() if len(row) > 3 and row[3] else ""
            attack_col = row[4].strip() if len(row) > 4 and row[4] else ""

            if set_num:
                current_set = {
                    "set_number": int(set_num),
                    "transactions": [],
                    "live": parse_node_list(live_col),
                    "byzantine": parse_node_list(byz_col),
                    "attacks": parse_attacks(attack_col)
                }
                test_sets.append(current_set)

            if current_set is not None and txn:
                current_set["transactions"].append(parse_transaction(txn))

    return test_sets



async def send_alive_parallel(live_nodes: set[int], kill_leader=False, 
                              prompting_pause=False, byzantine: set[int] = None, 
                              attacks: dict = None):
    """
    Send ALIVE messages to all nodes in parallel using persistent connections
    and wait for all ACKs before proceeding.
    """

    async def _send_to_node(node_id):
        websocket = persistent_connections.get(node_id)
        if websocket is None:
            # print(f"[Main] No persistent connection for node {node_id}")
            return

        is_alive = node_id in live_nodes
        is_byzantine = byzantine is not None and node_id in byzantine
        msg = {
            "type": "ALIVE",
            "alive": is_alive,
            "kill_leader": kill_leader,
            "prompting_pause": prompting_pause,
            "byzantine": is_byzantine,
            "attacks": attacks
        }

        try:
            await websocket.send(json.dumps(msg))
            # Wait for ACK
            ack_data = await websocket.recv()
            ack = json.loads(ack_data)
            #print(f"[Main] Node {node_id} ALIVE ack: {ack} (alive={is_alive})")
        except Exception as e:
            print(f"[Main] Failed to send ALIVE to node {node_id}: {e}")

    # Create tasks for all nodes
    tasks = [_send_to_node(node_id) for node_id in persistent_connections]
    await asyncio.gather(*tasks)


async def send_cancel():
    """
    Notify all connected nodes to cancel processing the current transaction.
    Works with persistent WebSocket connections.
    """
    msg = json.dumps({"type": "CANCEL"})
    cancel_tasks = []

    for node_id, websocket in persistent_connections.items():
        if websocket is None:
            print(f"[Main] No persistent connection to node {node_id} for CANCEL")
            continue

        async def _send_cancel(ws, nid):
            try:
                await ws.send(msg)
                # print(f"[Main] Sent CANCEL to node {nid}")
            except Exception as e:
                print(f"[Main] Failed to send CANCEL to node {nid}: {e}")

        cancel_tasks.append(_send_cancel(websocket, node_id))

    await asyncio.gather(*cancel_tasks)


# ---------------------------------------
# --- Async server to handle replies ----
# ---------------------------------------
async def handle_node_reply(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """
    Handles replies sent from nodes back to main.
    """
    addr = writer.get_extra_info('peername')
    print(f"[Reply Server] Connection from {addr}")
    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            msg = data.decode().strip()
            #print(f"[Reply Server] Received: {msg}")
    except Exception as e:
        print(f"[Reply Server] Error from {addr}: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def start_reply_server(host='127.0.0.1', port=6000):
    """
    Asyncio TCP server that listens for replies from nodes.
    """
    server = await asyncio.start_server(handle_node_reply, host, port)
    addr = server.sockets[0].getsockname()
    #print(f"[Reply Server] Listening on {addr}")
    async with server:
        await server.serve_forever()

# ---------------------------------------
# --- Launch node processes -------------
# ---------------------------------------
def start_nodes():
    """
    Starts node processes for ports 5001–5005.
    """
    procs = []
    base_port = 5000

    for i in range(1, config.NUM_NODES + 1):
        port = base_port + i
        p = subprocess.Popen(
            [sys.executable, "-u", "node_process.py", str(i), str(port), "6000"], 
            stdout=None,
            stderr=None,
        )
        #print(f"[Main] Started node {i} on port {port} (PID={p.pid})")
        procs.append(p)

    return procs


# ---------------------------------------
# --- Cleanup ---------------------------
# ---------------------------------------

async def cleanup(procs):
    print("[Main] Cleaning up...")
    for p in procs:
        p.terminate()


    ports = list(range(5001, 5007)) + list(range(6000, 6001 + config.NUM_CLIENTS))

    try:
        conns = psutil.net_connections()
    except psutil.AccessDenied:
        #print("[Main] Warning: Access denied when listing some connections.")
        conns = []

    for conn in conns:
        if conn.laddr and conn.laddr.port in ports and conn.pid:
            try:
                psutil.Process(conn.pid).kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    print("[Main] All ports cleared.")
    print("[Main] Orchestration complete.")
    os._exit(0)


def check_user_input(timeout=0.1):
    """Return user input if available within timeout seconds, else None."""
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip().lower()
    return None


async def get_status(msg):
    """
    Query all nodes for their status and print the results using persistent connections.
    """
    async def _query_node(node_id):

        ws = persistent_connections[int(node_id)]

        if ws is None:
            #print(f"[Main] No persistent connection to node {node_id}")
            return
        try:
            await ws.send(json.dumps(msg))

            # Wait for STATUS_RESPONSE from this node
            response_data = await ws.recv()
            response = json.loads(response_data)

            if msg["arg1"] == "printlog":
                print(f"[Node {node_id} Log]:")
                print(response.get("response", ""))
            elif msg["arg1"] == "printdb":
                print(f"[Node {node_id} DB]:")
                for client, amount in response.get("response", {}).items():
                    print(f"Client {client}: Balance {amount}")
                print("")
            elif msg["arg1"] == "printstatus":
                print(f"[Node {node_id} Status, Seq {msg['arg2']}]: {response.get('response', '')}")
            elif msg["arg1"] == "printview":
                
                return response.get('response', '')
            elif msg["arg1"] == "benchmark":
                return response.get('response', '')

        except Exception as e:
            print(f"[Main] Failed to query STATUS from node {node_id}: {e}")

    # Determine which nodes to query based on arg1
    if msg["arg1"] == "printlog":
        print(f"[Main] Querying log from node {msg['arg2']}")
        await _query_node(msg["arg2"])
    elif msg["arg1"] in ["printdb", "printstatus"]:
        for node_id in sorted(persistent_connections.keys()):
            await _query_node(node_id)
    elif msg["arg1"] == "printview":
        nv_set = set()
        for node_id in persistent_connections.keys():
            new_view_str_lst = await _query_node(node_id)
            for nv_str in new_view_str_lst:
                nv_set.add(nv_str)
        print("New View Logs Set:")
        for nv in nv_set:
            print(str(nv))
    elif msg["arg1"] == "benchmark":
        for node_id in persistent_connections.keys():
            benchmark_str = await _query_node(node_id)
            print(f"[Node {node_id} Benchmark]: {benchmark_str}")
    else:
        print("[Main] Unknown STATUS request.")

async def _connect_all_nodes():

    for node_id, (host, port) in config.nodes_info.items():
        uri = f"ws://{host}:{port}"
        websocket = await websockets.connect(uri, ping_interval=None)
        persistent_connections[int(node_id)] = websocket
        #print(f"[Main] Connected persistently to node {node_id}")


async def main():
    if len(sys.argv) != 2:
        #print("Usage: python orchestrator.py <input_file.csv>")
        sys.exit(1)

    filename = sys.argv[1]
    try:
        sets = read_test_file("test_files/" + filename)
    except FileNotFoundError:
        print(f"File not found: {filename}")
        sys.exit(1)

    procs = start_nodes()
    #print("[Main] Waiting for nodes to start...")
    await asyncio.sleep(.75) 
    for client in clients.values():
        client.start_loop()

    await asyncio.sleep(.5)

    await _connect_all_nodes()

    await asyncio.sleep(.25)

    #print("[Main] Orchestration started.")


    # have clients send heartbeat to nodes to establish connections
    for client_nme, client in clients.items():
        await client.send_heartbeat()


    for s in sets:
        # print(f"\n=== Set {s['set_number']} ===")
        # print(f"Transactions: {s['transactions']}")
        # print(f"Live Nodes: {s['live']}")
        # print(f"Byzantine Nodes: {s['byzantine']}")
        # print(f"Attacks: {s['attacks']}")

        # change sets in attack to be lists in place
        if "equivocation" in s['attacks']:
            s['attacks']['equivocation_set'] = list(s['attacks']['equivocation_set'])
        if "dark" in s['attacks']:
            s['attacks']['dark_set'] = list(s['attacks']['dark_set'])


        await send_alive_parallel(s['live'], byzantine=s['byzantine'], attacks=s['attacks'])

        cancel_event = threading.Event()


        transactions_still_need_to_given_to_clients = True
        txns_queue = deque(s['transactions'])
        while transactions_still_need_to_given_to_clients:
            
            start_time = time.time()
            while txns_queue:
                txn = txns_queue.popleft()
                if txn == "LF":
                    break
                client = clients[txn[0]]
                client.queue_transaction(txn)

            # print("[Main] Transactions started. Type 'cancel' to abort this set.")
            await asyncio.sleep(0.1)

            # In your main loop:
            while any(c.processing for c in clients.values()):
                user_input = check_user_input(0.1)
                if user_input == "cancel":
                    cancel_event.set()
                    # print("[Main] Cancel requested: skipping remaining transactions in this set.")
                    await send_cancel()
                    for c in clients.values():
                        c.handle_cancel()
            
            end_time = time.time()

            global throughput
            throughput = len(s['transactions']) / (end_time - start_time)

            # print([c.processing for c in clients.values()])
            # print("Cancel event:", cancel_event.is_set())

            if not txns_queue or cancel_event.is_set(): # all transaction divied out or cancel requested
                transactions_still_need_to_given_to_clients = False
                # cancel_thread.join(timeout=0.1)
                # print("[Main] All transactions processed or cancel requested.")
            else: # send synchronous alive updaet message
                # print("[Main] Hit Leader Fail")
                await send_alive_parallel({}, kill_leader=True)


        # kill nodes pre promoting
        # print("[Main] killing nodes pre-prompt")
        await send_alive_parallel({}, kill_leader=False, prompting_pause=True)

        # Prompt for continue after transactions
        while True:
            user_input = input(f"\nType 'Continue' to move to the next set ({s['set_number'] + 1}): ").strip().lower()
            user_input_list = user_input.split(" ")
            if user_input == "continue":
                break
            elif user_input_list[0] in ["printlog", "printdb", "printstatus", "printview"]:
                msg = {"type": "STATUS_REQUEST", "arg1": user_input_list[0]} 
                if len(user_input_list) > 1:
                    msg["arg2"] = user_input_list[1]
                
                if len(user_input_list) != 2 and user_input_list[0] in ["printlog", "printstatus"]:
                    print("[Main] Invalid command format.")
                    continue
                elif user_input_list[0] in ["printdb", "printview"] and len(user_input_list) != 1:
                    print("[Main] Invalid command format.")
                    continue

                await get_status(msg)
            elif user_input == "benchmark":
                print(f"[Main] Throughput: {throughput:.2f} txns/sec")
                print(f"[Main] Latencies: {config.latencies}")
                print(f"[Main] Average Latency: {sum(config.latencies) / len(config.latencies):.2f} sec")

                # send message to all nodes to get their cpu/mem benchmarks
                msg = {"type": "STATUS_REQUEST", "arg1": "benchmark"}
                await get_status(msg)
            elif user_input != "":
                print("[Main] Invalid command. Type 'Continue' to proceed to the next set.")



    await cleanup(procs)



if __name__ == "__main__":
    asyncio.run(main())