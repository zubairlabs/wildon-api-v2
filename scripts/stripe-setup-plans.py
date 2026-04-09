#!/usr/bin/env python3
"""
Create Wildon subscription products and prices in Stripe,
then update the local database subscription_plans with stripe_price_id.

Usage:
    # Using env var
    STRIPE_SECRET_KEY=sk_test_... python3 scripts/stripe-setup-plans.py

    # Or pass as argument
    python3 scripts/stripe-setup-plans.py sk_test_... [DATABASE_URL]

Requirements:
    pip install requests
"""

import json
import os
import subprocess
import sys

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package required. Install with: pip3 install requests")
    sys.exit(1)

STRIPE_KEY = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].startswith("sk_") else os.environ.get("STRIPE_SECRET_KEY", "")
DB_URL = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("DATABASE_URL", "postgresql://yugabyte@127.0.0.1:5433/wildon")

if not STRIPE_KEY:
    print("ERROR: STRIPE_SECRET_KEY not set. Pass as argument or set env var.")
    print("  STRIPE_SECRET_KEY=sk_test_... python3 scripts/stripe-setup-plans.py")
    sys.exit(1)

BASE = "https://api.stripe.com/v1"
AUTH = (STRIPE_KEY, "")

PLANS = [
    {
        "code": "go-monthly",
        "product_name": "Wildon Device Monthly",
        "description": "GPS watch monitoring — billed monthly",
        "price_cents": 999,
        "currency": "cad",
        "interval": "month",
    },
    {
        "code": "go-yearly",
        "product_name": "Wildon Device Yearly",
        "description": "GPS watch monitoring — billed yearly (save 20%)",
        "price_cents": 9588,
        "currency": "cad",
        "interval": "year",
    },
]


def stripe_post(path, data):
    resp = requests.post(f"{BASE}{path}", auth=AUTH, data=data)
    if not resp.ok:
        print(f"  Stripe error: {resp.status_code} {resp.text}")
        return None
    return resp.json()


def stripe_get(path, params=None):
    resp = requests.get(f"{BASE}{path}", auth=AUTH, params=params)
    if not resp.ok:
        return None
    return resp.json()


def find_existing_product(name):
    """Search for existing product by name to avoid duplicates."""
    result = stripe_get("/products", {"limit": 100, "active": "true"})
    if result and "data" in result:
        for product in result["data"]:
            if product["name"] == name:
                return product
    return None


def find_existing_price(product_id, interval, currency):
    """Find an active price for a product with matching interval."""
    result = stripe_get("/prices", {
        "product": product_id,
        "active": "true",
        "limit": 10,
    })
    if result and "data" in result:
        for price in result["data"]:
            recurring = price.get("recurring", {})
            if recurring.get("interval") == interval and price.get("currency") == currency:
                return price
    return None


def main():
    print("=" * 60)
    print("  Wildon Stripe Plan Setup")
    print(f"  Stripe: {'TEST' if 'test' in STRIPE_KEY else 'LIVE'} mode")
    print(f"  Database: {DB_URL}")
    print("=" * 60)
    print()

    updates = []

    for plan in PLANS:
        print(f"--- {plan['code']} ---")

        # Check for existing product
        existing = find_existing_product(plan["product_name"])
        if existing:
            product_id = existing["id"]
            print(f"  Product exists: {product_id}")
        else:
            product = stripe_post("/products", {
                "name": plan["product_name"],
                "description": plan["description"],
                "metadata[plan_code]": plan["code"],
                "metadata[app]": "wildon",
            })
            if not product:
                print(f"  FAILED to create product")
                continue
            product_id = product["id"]
            print(f"  Product created: {product_id}")

        # Check for existing price
        existing_price = find_existing_price(product_id, plan["interval"], plan["currency"])
        if existing_price:
            price_id = existing_price["id"]
            print(f"  Price exists: {price_id} ({plan['price_cents']}c/{plan['interval']})")
        else:
            price = stripe_post("/prices", {
                "product": product_id,
                "unit_amount": str(plan["price_cents"]),
                "currency": plan["currency"],
                "recurring[interval]": plan["interval"],
                "metadata[plan_code]": plan["code"],
            })
            if not price:
                print(f"  FAILED to create price")
                continue
            price_id = price["id"]
            print(f"  Price created: {price_id} ({plan['price_cents']}c/{plan['interval']})")

        updates.append((plan["code"], price_id, product_id))
        print()

    if not updates:
        print("No plans to update in database.")
        return

    # Update database
    print("--- Updating database ---")
    sql_parts = []
    for code, price_id, product_id in updates:
        sql_parts.append(
            f"UPDATE billing_app.subscription_plans "
            f"SET stripe_price_id = '{price_id}' "
            f"WHERE code = '{code}';"
        )

    full_sql = "\n".join(sql_parts)
    print(f"SQL:\n{full_sql}\n")

    try:
        result = subprocess.run(
            ["psql", DB_URL, "-c", full_sql],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            print(f"Database updated: {result.stdout.strip()}")
        else:
            print(f"psql error: {result.stderr.strip()}")
            print("\nRun the SQL above manually.")
    except FileNotFoundError:
        print("psql not found — run the SQL above manually against your database.")
    except Exception as e:
        print(f"Error: {e}")
        print("\nRun the SQL above manually.")

    print()
    print("=" * 60)
    print("  Setup complete!")
    print()
    print("  For mobile app Stripe integration, use this publishable key:")
    print(f"  pk_test_... (from your Stripe dashboard)")
    print()
    print("  Test card numbers:")
    print("    4242 4242 4242 4242  — Succeeds")
    print("    4000 0000 0000 0002  — Declined")
    print("    4000 0000 0000 3220  — Requires 3D Secure")
    print("=" * 60)


if __name__ == "__main__":
    main()
