#!/bin/bash

# Script to run Zig TFHE examples
# Usage: ./run_example.sh <example_name>

if [ $# -eq 0 ]; then
    echo "Usage: ./run_example.sh <example_name>"
    echo "Available examples:"
    echo "  add_two_numbers"
    echo "  gates_demo" 
    echo "  security_levels"
    exit 1
fi

EXAMPLE=$1
EXAMPLE_FILE="examples/${EXAMPLE}.zig"

if [ ! -f "$EXAMPLE_FILE" ]; then
    echo "Error: Example file $EXAMPLE_FILE not found"
    exit 1
fi

echo "Running example: $EXAMPLE"
echo "File: $EXAMPLE_FILE"
echo "----------------------------------------"

# Copy example to src directory temporarily
cp "$EXAMPLE_FILE" "src/temp_example.zig"

# Fix import path
sed -i '' 's|@import("../src/main.zig")|@import("main.zig")|g' "src/temp_example.zig"

# Run the example
zig run src/temp_example.zig -lc -lm

# Clean up
rm src/temp_example.zig

echo "----------------------------------------"
echo "Example complete!"