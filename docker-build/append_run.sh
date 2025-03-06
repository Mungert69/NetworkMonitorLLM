#!/bin/bash

# Check if the correct number of arguments is provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <file_name> <string_to_append>"
    exit 1
fi

# Assign arguments to variables
file_name="$1"
text_to_append="$2"
new_file_name="${file_name}_run"

# Check if the file exists
if [ ! -f "$file_name" ]; then
    echo "Error: File '$file_name' does not exist."
    exit 1
fi

# Create the new file with the appended text and an additional blank line
{
    cat "$file_name"
    echo "$text_to_append"
    echo ""
} > "$new_file_name"

echo "New file created: '$new_file_name'"
