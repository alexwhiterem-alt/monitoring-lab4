import json
import subprocess
import psycopg2
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
OSV_OUTPUT = "/tmp/osv_results.json"

def run_osv_scanner():
    print("Running osv-scanner...")
    result = subprocess.run(
        ["./osv-scanner", "--sbom", SBOM_FILE, "--format", "json", "--output", OSV_OUTPUT],
        capture_output=True, text=True
    )
    print(f"osv-scanner done: {result.returncode}")
    return os.path.exists(OSV_OUTPUT)

def parse_osv_results():
    with open(OSV_OUTPUT, "r") as f:
        return json.load(f)

def store_vulnerabilities(osv_data):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    collected_at = datetime.now()

    results = osv_data.get("results", [])
    vuln_count = 0

    for result in results:
        packages = result.get("packages", [])
        for pkg in packages:
            pkg_info = pkg.get("package", {})
            pkg_name = pkg_info.get("name", "")
            pkg_version = pkg_info.get("version", "")
            ecosystem = pkg_info.get("ecosystem", "")

            for vuln in pkg.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "")
                summary = vuln.get("summary", "")

                # Определяем severity
                severity = "UNKNOWN"
                database_specific = vuln.get("database_specific", {})
                if database_specific.get("severity"):
                    severity = database_specific["severity"]
                else:
                    for affected in vuln.get("affected", []):
                        db_spec = affected.get("database_specific", {})
                        if db_spec.get("severity"):
                            severity = db_spec["severity"]
                            break

                # Сохраняем уязвимость
                cur.execute("""
                    INSERT INTO vulnerabilities (vuln_id, severity, summary, collected_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                """, (vuln_id, severity, summary, collected_at))

                # Сохраняем связь пакет-уязвимость
                cur.execute("""
                    INSERT INTO package_vulnerabilities (package_name, package_version, vuln_id, ecosystem, collected_at)
                    VALUES (%s, %s, %s, %s, %s)
                """, (pkg_name, pkg_version, vuln_id, ecosystem, collected_at))

                vuln_count += 1

    conn.commit()
    cur.close()
    conn.close()
    print(f"Stored {vuln_count} vulnerability records")
    return vuln_count

def main():
    if not os.path.exists(SBOM_FILE):
        print(f"SBOM file not found: {SBOM_FILE}, run scan_and_store.py first")
        return

    if run_osv_scanner():
        osv_data = parse_osv_results()
        store_vulnerabilities(osv_data)
    else:
        print("osv-scanner failed or no results!")

if __name__ == "__main__":
    main()