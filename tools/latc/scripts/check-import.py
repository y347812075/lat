#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main() -> int:
    manifest = json.loads((ROOT / "cfg-import.json").read_text())
    missing = []
    for kind in ("modified", "added"):
        for rel in manifest[kind]:
            if not (ROOT / "cfg" / rel).is_file():
                missing.append(f"{kind}: cfg/{rel}")
    if missing:
        print("import check failed")
        for item in missing:
            print(f"  missing {item}")
        return 1
    lat_manifest = ROOT / "lat-import.json"
    if lat_manifest.exists():
        lat = json.loads(lat_manifest.read_text())
        for item in lat.get("files", []):
            path = ROOT / item["local_path"]
            if not path.is_file():
                missing.append(item["local_path"])
        if missing:
            print("LAT import check failed")
            for item in missing:
                print(f"  missing {item}")
            return 1
        print(f"lat import OK commit={lat['source_commit']} files={lat['file_count']}")
    local_manifest = ROOT / "lat-local.json"
    if local_manifest.exists():
        local = json.loads(local_manifest.read_text())
        for item in local.get("added", []) + local.get("modified", []):
            if not (ROOT / item["path"]).is_file():
                missing.append(item["path"])
        if missing:
            print("LAT local change check failed")
            for item in missing:
                print(f"  missing {item}")
            return 1
        print(f"lat local changes OK added={len(local.get('added', []))} "
              f"modified={len(local.get('modified', []))}")
    print(f"cfg import OK commit={manifest['commit']} usage={manifest['usage']}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
