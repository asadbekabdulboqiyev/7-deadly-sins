"""To'liq oqim demosi: nishon -> egalik -> skan -> topilmalar -> PDF.

Talab: API (`sins serve`) va worker (`sins worker`) ishlab turishi kerak.

Ishlatish:
    SINS_API_KEY=sins_... uv run python scripts/e2e_demo.py http://localhost:8099
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx

BASE = os.environ.get("SINS_API_BASE", "http://127.0.0.1:8000")
API_KEY = os.environ.get("SINS_API_KEY", "")
TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8099"


def main() -> int:
    if not API_KEY:
        print("XATO: SINS_API_KEY env o'zgaruvchisi kerak.")
        return 2

    headers = {"X-API-Key": API_KEY}
    with httpx.Client(base_url=BASE, headers=headers, timeout=60) as client:
        health = client.get("/healthz").json()
        print(f"1. healthz: {health}")

        created = client.post("/targets", json={"value": TARGET})
        created.raise_for_status()
        target = created.json()
        print(
            f"2. nishon: {target['value']} ({target['kind']}), tasdiqlangan: "
            f"{target['verified_at'] is not None}"
        )

        if target["verified_at"] is None:
            print("   Egalik tasdiqlanmagan — ko'rsatma:", target["instructions"])
            return 3

        scan = client.post("/scans", json={"target_id": target["id"]}).json()
        scan_id = scan["id"]
        print(f"3. skan yaratildi: {scan_id} ({scan['status']}), engine: {scan['engines']}")

        deadline = time.time() + 900
        last = ""
        while time.time() < deadline:
            state = client.get(f"/scans/{scan_id}").json()
            engine = state.get("current_engine") or ""
            line = f"   {state['status']:8s} {state['progress']:3d}% {engine}"
            if line != last:
                print(line)
                last = line
            if state["status"] in {"done", "failed", "blocked"}:
                break
            time.sleep(2)
        else:
            print("XATO: skan vaqtida tugamadi.")
            return 4

        if state["status"] != "done":
            print(f"XATO: skan {state['status']}: {state.get('error')}")
            return 5

        findings = client.get(f"/scans/{scan_id}/findings").json()
        print(f"4. topilmalar: {findings['total']} ta")
        for item in findings["items"][:5]:
            print(f"   [{item['severity']:8s}] {item['title'][:70]}")

        report = client.get(f"/scans/{scan_id}/report.pdf")
        report.raise_for_status()
        out = Path("out/api-report.pdf")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(report.content)
        print(f"5. PDF: {out} ({len(report.content) // 1024} KB)")
        print(f"   API: {BASE}/docs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
