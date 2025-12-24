import sys
import asyncio
from node import Node
from config import nodes_info, NUM_CLIENTS, client_keys, node_keys, all_public_keys, bls_node_keys, bls_node_public_keys

client_addr = {chr(ord('A') + i): ("127.0.0.1", 6001 + i) for i in range(NUM_CLIENTS)}

async def main():
    node_id = int(sys.argv[1])
    port = int(sys.argv[2])
    main_port = int(sys.argv[3])

    node = Node(
        node_id=node_id,
        port=port,
        main_port=main_port,
        nodes=nodes_info,
        client_addr=client_addr,
        private_key=node_keys[node_id],
        all_public_keys=all_public_keys,
        bls_node_key=bls_node_keys[node_id],
        bls_node_public_keys=bls_node_public_keys
    )

    # Start the WebSocket server in the background
    asyncio.create_task(node.run_ws_server())

    # Wait a moment to ensure the server is listening
    await asyncio.sleep(0.2)

    # Connect to all peers (persistent WebSocket)
    await node.connect_to_all_nodes()

    # print(f"[Node {node_id}] WebSocket server started and connected to peers.")

    # Keep running indefinitely
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())