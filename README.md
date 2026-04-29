# Linear PBFT — Practical Byzantine Fault Tolerance (LPBFT)

A small application implementing a linear variant of Practical Byzantine Fault Tolerance (PBFT). The protocol provides state-machine replication with tolerance to Byzantine nodes under different attacks including crash, signature, equivocation, in-dark and time. 

## Features Implemented
 1. Checkpointing Mechanism - Allows replicas to transfer only checkpointed state summaries during view changes, avoiding the need to resend all previously prepared messages.
 2. Phase Linearization - Replaces the all-to-all communication in the prepare and commit phases with a collector-based pattern to achieve linear message complexity. Instead of each replica broadcasting to all others (O(n²)), replicas send their prepare/commit messages to a designated collector, which aggregates 2f + 1 signatures and broadcasts a single certificate back to all replicas. This preserves PBFT safety via quorum intersection while reducing communication overhead to O(n) per phase
 3. Threshold Signatures - Using threshold signatures, the collector message size becomes
constant, e.g., instead of sending 2f + 1 commit messages to all backups to let them
know the message has been committed, it sends a single commit message signed by
2f + 1 nodes using a threshold signature.

4. Optimistic Phase reduction - if 3f other prepares are gathered (in this case that is all nodes prepare the message) the third phase can be omitted and replicas can directly commit the request. Otherwise falls back onto normal protocol 

5. Benchamrking - Tested performance of the application with larger number of transactions and accounts. Throughput, latency, cpu utilization and memory usage per node process were logged.


## How to run
I used Python 3.12

1. Clone repository
```bash
    - git clone <repo>
```

2. make sure bls packages are pip installed and also that ports 5001 - 7 and 6000 - 6010 are not in use 

3. Generate the keys for signures

```bash
python generate_keys.py
```

4. Run the program:

```bash
python orcestrator.py <text_file_name>
```


5. Commands After Set completion to see System State:

* if a command does not finish it can be canceled with the command: cancel

View the logs containing sent and received messages for a node
```bash
PrintLog <node_id>
```

Print the state of each node
```bash
PrintDB
```

print the status of the transaction corresponding with a certain sequence number
```bash
PrintStatus <seqnum>
```

View all new views that ocurred during processing
```bash
PrintView
```

View benchmarking statistics such as latency, throughhput, cpu utilization and memory utilization (max and avg)
```bash
Benchmark
```


## Logs

logs for message types should be conssitent with those described in the notes and the paper 

## References

1. https://css.csail.mit.edu/6.824/2014/papers/castro-practicalbft.pdf

