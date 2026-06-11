import json
import subprocess
import psycopg2
import uuid
import os
from datetime import datetime

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "monitoring",
    "user": "monitor",
    "password": "monitor123"
}

SBOM_FILE = "/tmp/sbom_scan.json"

def run_cdxgen():
    print("Running cdxgen...")
    result = subprocess.run(
        ["cdxgen", "-t", "os", "--spec-version", "1.4", "-o", SBOM_FILE],
        capture_output=True, text=True
    )
    print(f"cdxgen done: {result.returncode}")
    return result.returncode == 0

def parse_sbom():
    with open(SBOM_FILE, "r") as f:
        return json.load(f)

def get_os_info(sbom):
    metadata = sbom.get("metadata", {})
    component = metadata.get("component", {})
    properties = {p["name"]: p["value"] for p in component.get("properties", [])}

    return {
        "name": properties.get("cdx:osName", component.get("name", "Ubuntu")),
        "version": properties.get("cdx:osVersion", component.get("version", "")),
        "arch": properties.get("cdx:arch", "x86_64"),
        "os_id": properties.get("cdx:osId", "ubuntu"),
        "version_id": properties.get("cdx:osVersionId", "22.04"),
        "description": component.get("description", "Ubuntu 22.04 LTS"),
        "codename": properties.get("cdx:osCodename", "jammy")
    }

def store_data(sbom):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    asset_id = str(uuid.uuid4())
    collected_at = datetime.now()

    # Сохраняем информацию об ОС
    os_info = get_os_info(sbom)
    cur.execute("""
        INSERT INTO os_info (asset_id, name, version, arch, os_id, version_id, description, codename, collected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        asset_id, os_info["name"], os_info["version"], os_info["arch"],
        os_info["os_id"], os_info["version_id"], os_info["description"],
        os_info["codename"], collected_at
    ))

    # Сохраняем пакеты
    components = sbom.get("components", [])
    pkg_count = 0
    for comp in components:
        name = comp.get("name", "")
        version = comp.get("version", "")
        if not name:
            continue
        cur.execute("""
            INSERT INTO packages (asset_id, name, version, arch, description, collected_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (asset_id, name, version, "x86_64", comp.get("description", ""), collected_at))
        pkg_count += 1

    conn.commit()
    cur.close()
    conn.close()

    print(f"Stored OS info and {pkg_count} packages with asset_id={asset_id}")
    return asset_id

def main():
    if run_cdxgen():
        sbom = parse_sbom()
        store_data(sbom)
    else:
        print("cdxgen failed!")

if __name__ == "__main__":
    main()