#!/usr/bin/env python3
# xwallet_root_helper.py — PRO raw scanner (no GUI, only console)
# Запускається як root через pkexec / usr/bin/xwallet-root-helper

from __future__ import annotations
import os
import re
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# --------- базові налаштування ---------

USER_HOME = Path("/home/xx")   # <- твій користувач
RESULTS_ROOT = USER_HOME / "xwallet_scan_results"
RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

MNEMONIC_RE = re.compile(r'\b([a-z]{3,})\b(?:\s+\b([a-z]{3,})\b){11,23}', re.IGNORECASE)
ETH_PRIV_RE = re.compile(r'0x[a-fA-F0-9]{64}')
HEX64_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def ts_dir() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)

def ensure_result_dir(label: str) -> Path:
    safe = re.sub(r"[^0-9A-Za-z._-]+", "_", label)[:40]
    out = RESULTS_ROOT / f"{ts_dir()}_{safe}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "raw").mkdir(exist_ok=True)
    (out / "found").mkdir(exist_ok=True)
    return out

# --------- вибір пристроїв ---------

def list_block_devices() -> List[dict]:
    """
    Повертає список dict: {"dev": "/dev/nvme0n1", "name": "nvme0n1", "type": "disk/part", "tran": "nvme/usb/…"}
    """
    devices: List[dict] = []
    try:
        out = subprocess.check_output(
            ["lsblk", "-ndo", "NAME,TYPE,TRAN"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        log(f"lsblk error: {e}")
        return devices

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) == 2:
            name, typ = parts
            tran = ""
        else:
            name, typ, tran = parts[0], parts[1], parts[2]
        dev = f"/dev/{name}"
        if typ not in ("disk", "part"):
            continue
        devices.append({"dev": dev, "name": name, "type": typ, "tran": tran})
    return devices

def filter_devices(mode: str) -> List[dict]:
    all_devs = list_block_devices()
    if mode == "nvme":
        return [d for d in all_devs if d["name"].startswith("nvme")]
    if mode == "usb":
        return [d for d in all_devs if d.get("tran") == "usb"]
    return [d for d in all_devs if d["name"].startswith(("sd", "nvme"))]

# --------- raw-скан одного пристрою ---------

def scan_device_raw(dev: str, outdir: Path, limit_mb: int = 0, chunk_mb: int = 4) -> None:
    """
    Пряме читання /dev/... з пошуком seed/private key. Пише результати у NDJSON.
    """
    log(f"Scanning RAW: {dev}")
    raw_dir = outdir / "raw"
    raw_dir.mkdir(exist_ok=True)
    found_dir = outdir / "found"
    found_dir.mkdir(exist_ok=True)

    hits_path = found_dir / f"{os.path.basename(dev)}_raw_hits.ndjson"
    stats = {"secrets_found": 0, "bytes_read": 0, "device": dev}
    limit_bytes = limit_mb * 1024 * 1024 if limit_mb > 0 else 0

    # отримати розмір блочного пристрою (для %)
    size_bytes = 0
    try:
        size_bytes = int(
            subprocess.check_output(
                ["blockdev", "--getsize64", dev],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        )
    except Exception:
        pass

    chunk_size = chunk_mb * 1024 * 1024

    try:
        with open(dev, "rb", buffering=0) as f, hits_path.open("w", encoding="utf-8") as hits:
            offset = 0
            while True:
                buf = f.read(chunk_size)
                if not buf:
                    break
                offset += len(buf)
                stats["bytes_read"] = offset

                # відсотки
                if size_bytes > 0:
                    perc = int(offset * 100 / size_bytes)
                    log(f"Progress {dev}: {perc}%")
                else:
                    log(f"Progress {dev}: {offset // (1024*1024)} MB read")

                # пошук патернів
                try:
                    text = buf.decode("utf-8", errors="ignore")
                except Exception:
                    text = ""

                found_here = False
                if text:
                    if MNEMONIC_RE.search(text):
                        hit = {
                            "type": "mnemonic_raw",
                            "device": dev,
                            "offset": offset,
                            "snippet": text[:200],
                        }
                        hits.write(json.dumps(hit, ensure_ascii=False) + "\n")
                        stats["secrets_found"] += 1
                        found_here = True
                        log(f"FOUND mnemonic at approx {offset} bytes on {dev}")
                    if ETH_PRIV_RE.search(text):
                        hit = {
                            "type": "eth_priv_raw",
                            "device": dev,
                            "offset": offset,
                            "snippet": text[:200],
                        }
                        hits.write(json.dumps(hit, ensure_ascii=False) + "\n")
                        stats["secrets_found"] += 1
                        found_here = True
                        log(f"FOUND ETH privkey-like fragment at {offset} bytes on {dev}")
                    if (not found_here) and HEX64_RE.search(text):
                        hit = {
                            "type": "hex64_raw",
                            "device": dev,
                            "offset": offset,
                            "snippet": text[:200],
                        }
                        hits.write(json.dumps(hit, ensure_ascii=False) + "\n")
                        stats["secrets_found"] += 1
                        log(f"FOUND generic 64-hex fragment at {offset} bytes on {dev}")

                if limit_bytes and offset >= limit_bytes:
                    log(f"Limit {limit_mb} MB reached on {dev}, stopping")
                    break

        # записати summary
        with (found_dir / f"{os.path.basename(dev)}_raw_summary.json").open(
            "w", encoding="utf-8"
        ) as sf:
            json.dump(stats, sf, ensure_ascii=False, indent=2)

    except PermissionError:
        log(f"Permission error on {dev} (need root)")
    except Exception as e:
        log(f"Error scanning {dev}: {e}")

# --------- main ---------

def main(argv: list[str]) -> None:
    mode = "full"
    limit_mb = 0
    chunk_mb = 4

    # простенький парсер аргументів
    for arg in argv[1:]:
        if arg.startswith("--mode="):
            mode = arg.split("=", 1)[1]
        elif arg.startswith("--limit-mb="):
            try:
                limit_mb = int(arg.split("=", 1)[1])
            except ValueError:
                pass
        elif arg.startswith("--chunk-mb="):
            try:
                chunk_mb = int(arg.split("=", 1)[1])
            except ValueError:
                pass

    log(f"Running PRO raw scanner as root (mode={mode}, limit_mb={limit_mb}, chunk_mb={chunk_mb})")

    devices = filter_devices(mode)
    if not devices:
        log("No suitable devices found")
        return

    for d in devices:
        dev = d["dev"]
        out = ensure_result_dir(os.path.basename(dev))
        scan_device_raw(dev, outdir=out, limit_mb=limit_mb, chunk_mb=chunk_mb)

    log("RAW scan complete")

if __name__ == "__main__":
    main(sys.argv)
