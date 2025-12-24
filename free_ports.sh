#!/bin/bash

# Loop over ports 5001 to 5005
for port in {5001..5007}
do
    # Find the PID(s) using the port
    pids=$(lsof -t -i :$port)

    if [ -n "$pids" ]; then
        echo "Killing process(es) on port $port: $pids"
        kill -9 $pids
    else
        echo "No process found on port $port"
    fi
done

for port in {6001..6010}
do
    # Find the PID(s) using the port
    pids=$(lsof -t -i :$port)

    if [ -n "$pids" ]; then
        echo "Killing process(es) on port $port: $pids"
        kill -9 $pids
    else
        echo "No process found on port $port"
    fi
done
