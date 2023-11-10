#!/bin/bash

# Number of times to start the executable
count=1

# Start the executables in parallel
for ((i=0; i<$count; i++)); do
    taskset -c $i ./target/release/circ_executable 1 100 &  # '&' runs the process in the background
done

# Wait for all background processes to finish
wait

echo "All processes have finished."
