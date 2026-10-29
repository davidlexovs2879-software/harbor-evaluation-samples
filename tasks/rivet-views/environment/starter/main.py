#!/usr/bin/env python3
"""Rivet JSON-line transport. Implement the relational engine behind this interface."""
import json
import sys

for line in sys.stdin:
    try:
        json.loads(line)
        response = {"error": "unimplemented"}
    except ValueError:
        response = {"error": "invalid"}
    print(json.dumps(response), flush=True)
