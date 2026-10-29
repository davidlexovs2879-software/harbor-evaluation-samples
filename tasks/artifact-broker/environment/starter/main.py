#!/usr/bin/env python3
"""Legacy broker transport. Its authorization and storage paths need replacement."""
import json
import sys


def main():
    objects = {}
    for line in sys.stdin:
        try:
            request = json.loads(line)
            # Legacy clients used a path alone as the object identity.
            path = request.get("path", "")
            if request["op"] == "write":
                objects[path] = request["data"]
                response = {"status": 200, "body": {"ok": True}}
            elif request["op"] == "read":
                response = {"status": 200, "body": {"data": objects.get(path, "")}}
            else:
                response = {"status": 400, "body": {"error": "invalid"}}
        except (ValueError, KeyError, TypeError, AttributeError):
            response = {"status": 400, "body": {"error": "invalid"}}
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
