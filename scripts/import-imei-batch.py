#!/usr/bin/env python3
"""
Bulk import IMEIs from a CSV file into device_inventory.

Usage:
    python3 scripts/import-imei-batch.py <csv_file> [DATABASE_URL]

CSV format (with header):
    IMEI,MODEL
    353456789012345,L16
    353456789012346,L17PRO

Or without header (auto-detected if first line is 15 digits):
    353456789012345,L16
"""

import csv
import hashlib
import subprocess
import sys


def sha256(imei):
    return hashlib.sha256(imei.encode()).hexdigest()


def normalize_imei(raw):
    return raw.strip().replace("-", "").replace(" ", "")


def validate_imei(imei):
    return len(imei) == 15 and imei.isdigit()


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 import-imei-batch.py <csv_file> [DATABASE_URL] [BATCH_ID] [SUPPLIER]")
        sys.exit(1)

    csv_file = sys.argv[1]
    db_url = sys.argv[2] if len(sys.argv) > 2 else "postgresql://yugabyte@127.0.0.1:5433/wildon"
    batch_id = sys.argv[3] if len(sys.argv) > 3 else "IMPORT_BATCH"
    supplier = sys.argv[4] if len(sys.argv) > 4 else "Unknown"

    print(f"=== Importing IMEIs from {csv_file} ===")
    print(f"Database: {db_url}")
    print(f"Batch: {batch_id}")
    print(f"Supplier: {supplier}")
    print()

    items = []
    errors = []

    with open(csv_file, "r") as f:
        reader = csv.reader(f)
        first_row = next(reader)

        # Detect header
        if first_row[0].strip().upper() in ("IMEI", "imei"):
            pass  # skip header
        else:
            # First row is data
            imei = normalize_imei(first_row[0])
            model = first_row[1].strip() if len(first_row) > 1 else "L16"
            if validate_imei(imei):
                items.append((imei, model))
            else:
                errors.append(f"Invalid IMEI: {first_row[0]}")

        for row in reader:
            if not row or not row[0].strip():
                continue
            imei = normalize_imei(row[0])
            model = row[1].strip() if len(row) > 1 else "L16"
            if validate_imei(imei):
                items.append((imei, model))
            else:
                errors.append(f"Invalid IMEI: {row[0]}")

    if errors:
        print(f"Errors ({len(errors)}):")
        for e in errors:
            print(f"  - {e}")
        print()

    if not items:
        print("No valid IMEIs to import.")
        sys.exit(1)

    print(f"Valid IMEIs: {len(items)}")

    values = []
    for imei, model in items:
        imei_hash = sha256(imei)
        values.append(
            f"('{imei}', '{imei_hash}', '{model}', '{batch_id}', '{supplier}')"
        )

    sql = f"""
INSERT INTO care_app.device_inventory (imei, imei_hash, model_code, batch_id, supplier)
VALUES
  {',\n  '.join(values)}
ON CONFLICT (imei) DO NOTHING;
"""

    try:
        result = subprocess.run(
            ["psql", db_url, "-c", sql],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            print(f"\nResult: {result.stdout.strip()}")
        else:
            print(f"\npsql error: {result.stderr.strip()}")
            print("\nSQL for manual execution:")
            print(sql)
    except FileNotFoundError:
        print("\npsql not found. SQL for manual execution:")
        print(sql)
    except Exception as e:
        print(f"\nError: {e}")
        print("\nSQL for manual execution:")
        print(sql)


if __name__ == "__main__":
    main()
