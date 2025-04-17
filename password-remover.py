import os
import sys
import json
import argparse


def sanitize(obj, property_names):
    """
    Recursively traverse the JSON-like object `obj` and replace any value whose key
    exactly matches one of the specified `property_names` with the string ".env".
    """
    if isinstance(obj, dict):
        for key, value in list(obj.items()):
            # If the property name matches, replace its value
            if key in property_names:
                obj[key] = ".env"
            else:
                obj[key] = sanitize(value, property_names)
        return obj

    elif isinstance(obj, list):
        return [sanitize(item, property_names) for item in obj]

    # For other data types, return as-is
    return obj


def process_file(path, property_names, backup):
    """
    Load JSON from `path`, sanitize it based on `property_names`, and write back.
    Optionally back up the original.
    """
    with open(path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Skipping '{path}': JSON decode error: {e}")
            return

    sanitized = sanitize(data, property_names)

    if backup:
        backup_path = f"{path}.bak"
        os.replace(path, backup_path)
        print(f"Backed up original to: {backup_path}")

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(sanitized, f, indent=2)
    print(f"Sanitized: {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Sanitize JSON files by replacing values of specified properties with '.env'."
    )
    parser.add_argument(
        'path',
        help='Path to a JSON file or directory containing JSON files'
    )
    parser.add_argument(
        '--properties',
        required=True,
        help='Comma-separated list of exact property names whose values should be replaced'
    )
    parser.add_argument(
        '--backup',
        action='store_true',
        help='Back up original files with a .bak extension before overwriting'
    )
    args = parser.parse_args()

    property_names = [name.strip() for name in args.properties.split(',') if name.strip()]

    if os.path.isdir(args.path):
        for root, dirs, files in os.walk(args.path):
            for fname in files:
                if fname.lower().endswith('.json'):
                    process_file(os.path.join(root, fname), property_names, args.backup)
    elif os.path.isfile(args.path):
        process_file(args.path, property_names, args.backup)
    else:
        print(f"Error: Path not found: {args.path}")
        sys.exit(1)


if __name__ == '__main__':
    main()

