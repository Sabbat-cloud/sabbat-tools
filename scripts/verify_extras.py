#!/usr/bin/env python3
import importlib.util, sys, os, json

EXTRAS = {
    "geoip": ("geoip2", "GeoIP2 features enabled"),
    "yara": ("yara", "YARA scanning enabled"),
}

missing = []
for name, (module, desc) in EXTRAS.items():
    if importlib.util.find_spec(module) is None:
        missing.append({"extra": name, "module": module, "desc": desc})

if missing:
    print(json.dumps({"ok": False, "missing": missing}, indent=2))
    sys.exit(1)
print(json.dumps({"ok": True}))
