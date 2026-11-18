#!/usr/bin/env python3
"""Create / update the BOD 26-04 hunt saved searches on Splunk via REST.

Run on your Mac (needs access to the management port 8089 of the stack):
    export SPLUNK_URL=https://<your-stack>.splunkcloud.com:8089
    read -s SPLUNK_TOKEN && export SPLUNK_TOKEN      # paste a Splunk auth token, not echoed
    python3 create_saved_searches.py              # add --dry-run to only print
Creates the searches in app "search", shared globally (read: everyone).
"""
import json, os, ssl, sys, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from templates import T

URL = os.environ.get("SPLUNK_URL", "https://<your-stack>.splunkcloud.com:8089").rstrip("/")
TOKEN = os.environ.get("SPLUNK_TOKEN", "")
APP = "search"
DRY = "--dry-run" in sys.argv
CTX = ssl.create_default_context()


def call(method, path, data=None):
    body = urllib.parse.urlencode(data or {}, doseq=True).encode() if data is not None else None
    req = urllib.request.Request(URL + path + ("&" if "?" in path else "?") + "output_mode=json", data=body, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def main():
    if not DRY and not TOKEN:
        sys.exit("Set SPLUNK_TOKEN first (read -s SPLUNK_TOKEN && export SPLUNK_TOKEN).")
    base = f"/servicesNS/nobody/{APP}/saved/searches"
    for name, (desc, spl) in T.items():
        fields = {"search": spl, "description": desc, "disabled": "0", "is_scheduled": "0",
                  "dispatch.earliest_time": "-7d@h", "dispatch.latest_time": "now"}
        if DRY:
            print(f"--- {name}\n{spl}\n"); continue
        st, _ = call("GET", f"{base}/{urllib.parse.quote(name)}")
        if st == 200:
            st, out = call("POST", f"{base}/{urllib.parse.quote(name)}", fields); action = "updated"
        else:
            st, out = call("POST", base, dict(fields, name=name)); action = "created"
        if st not in (200, 201):
            print(f"FAIL {name}: HTTP {st} {out[:300]}"); continue
        st2, out2 = call("POST", f"{base}/{urllib.parse.quote(name)}/acl",
                         {"sharing": "global", "owner": "nobody", "perms.read": "*", "perms.write": "admin"})
        print(f"OK   {name}: {action}" + ("" if st2 == 200 else f" (ACL HTTP {st2}: {out2[:200]})"))


if __name__ == "__main__":
    main()
