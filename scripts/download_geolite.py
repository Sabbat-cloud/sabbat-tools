#!/usr/bin/env python3
import argparse, os, sys, tarfile, tempfile, shutil, urllib.request, json

URL = "https://download.maxmind.com/app/geoip_download"
# Nota: MaxMind requiere cuenta y licencia; se usa Country DB como ejemplo.

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--license-key", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    params = f"?edition_id=GeoLite2-Country&license_key={args.license_key}&suffix=tar.gz"
    url = URL + params

    with tempfile.TemporaryDirectory() as d:
        tgz = os.path.join(d, "geo.tgz")
        urllib.request.urlretrieve(url, tgz)
        with tarfile.open(tgz, "r:gz") as tf:
            mmdb = [m for m in tf.getmembers() if m.name.endswith(".mmdb")][0]
            tf.extract(mmdb, d)
            src = os.path.join(d, mmdb.name)
            os.makedirs(os.path.dirname(args.out), exist_ok=True)
            shutil.copy2(src, args.out)

    print(json.dumps({"status":"ok","path":args.out}))

if __name__ == "__main__":
    main()
