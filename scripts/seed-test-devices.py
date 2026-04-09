#!/usr/bin/env python3
"""
Seed 10 test devices into device_inventory for development.

Usage:
    python3 scripts/seed-test-devices.py [DATABASE_URL]

Defaults to: postgresql://yugabyte@127.0.0.1:5433/wildon
"""

import hashlib
import random
import subprocess
import sys


def generate_imei():
    """Generate a random 15-digit IMEI-like number."""
    # TAC (8 digits) + serial (6 digits) + check (1 digit)
    tac = "35934907"  # fake TAC prefix
    serial = "".join([str(random.randint(0, 9)) for _ in range(6)])
    partial = tac + serial
    # Luhn check digit
    digits = [int(d) for d in partial]
    for i in range(1, len(digits), 2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    check = (10 - sum(digits) % 10) % 10
    return partial + str(check)


def sha256(imei):
    return hashlib.sha256(imei.encode()).hexdigest()



# Fixed test IMEIs — these match the fleet simulator
TEST_IMEIS = [
    "359349071043325",  # CN Tower, Downtown Toronto
    "359349071819609",  # North York Centre
    "359349070133895",  # Square One, Mississauga
    "359349070838634",  # Markham Civic Centre
    "359349077940268",  # Brampton City Hall
    "359349075423515",  # Vaughan Mills Mall
    "359349071615593",  # Scarborough Town Centre
    "359349074078161",  # Brampton Shoppers World
    "359349071849598",  # Pickering Town Centre
    "359349073103416",  # Little Italy, Toronto
]


def main():
    db_url = sys.argv[1] if len(sys.argv) > 1 else "postgresql://yugabyte@127.0.0.1:5433/wildon"
    batch_id = "SEED_TEST_2026_03"
    model = "L16"

    imeis = TEST_IMEIS
    count = len(imeis)

    print(f"=== Seeding {count} test devices ===")
    print(f"Database: {db_url}")
    print(f"Model: {model}")
    print(f"Batch: {batch_id}")
    print()

    values = []
    for imei in imeis:
        imei_hash = sha256(imei)
        values.append(
            f"('{imei}', '{imei_hash}', '{model}', '{batch_id}', 'JiAi Medical')"
        )

    sql = f"""
INSERT INTO care_app.device_inventory (imei, imei_hash, model_code, batch_id, supplier)
VALUES
  {',\n  '.join(values)}
ON CONFLICT (imei) DO NOTHING;
"""

    print("SQL:")
    print(sql)

    # Try to execute via psql
    try:
        result = subprocess.run(
            ["psql", db_url, "-c", sql],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print(f"Success: {result.stdout.strip()}")
        else:
            print(f"psql error: {result.stderr.strip()}")
            print("\nYou can run the SQL manually.")
    except FileNotFoundError:
        print("psql not found — run the SQL above manually against your database.")
    except Exception as e:
        print(f"Error: {e}")
        print("\nRun the SQL above manually.")

    print("\n=== Generated IMEIs (use with watch simulator) ===")
    for i, imei in enumerate(imeis, 1):
        print(f"  {i:2d}. {imei}")

    print(f"\nTo test activation:")
    print(f'  curl -X POST http://localhost:8080/v1/devices/activate/imei \\')
    print(f'    -H "Content-Type: application/json" \\')
    print(f'    -d \'{{"imei": "{imeis[0]}", "name": "Test Watch 1"}}\'')

    print(f"\nTo test with watch simulator:")
    print(f"  python3 scripts/test-watch-simulator.py 127.0.0.1 9000")
    print(f"  (then update IMEI in the script to one of the above)")


if __name__ == "__main__":
    main()
