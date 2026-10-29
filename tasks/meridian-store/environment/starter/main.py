#!/usr/bin/env python3
"""Meridian command loop. Replace the placeholder engine with a durable implementation."""
import json
import sys


def main():
    for line in sys.stdin:
        try:
            json.loads(line)
            reply = {"error": "unimplemented"}
        except (ValueError, TypeError):
            reply = {"error": "invalid"}
        print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
