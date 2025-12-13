#!/usr/bin/env python3
"""
xWallet SELF-TEST: перевіряє GUI, root-helper, диски, PyQt5, середовище та результати.
"""

import os, sys, subprocess, time, json
from pathlib import Path

HOME = Path(os.path.expanduser("~"))
RESULTS = HOME / "xwallet_scan_results"
WRAPPER = Path("/usr/bin/xwallet-pro-root")
ROOT_HELPER = Path("/usr/bin/xwallet-root-helper")

print("=== xWallet SELF-TEST START ===")

# 1. Перевірка Python середовища
print("[1] Python OK:", sys.executable)

# 2. Перевірка PyQt5
try:
    import PyQt5
    try:
        ver = PyQt5.__version__
    except:
        ver = "OK (version attribute missing)"
    print("[2] PyQt5 found:", ver)
except Exception as e:
    print("[2] PyQt5 ERROR:", e)
    sys.exit(1)

# 3. Перевірка директорій
print("[3] Checking directories:")
for d in [RESULTS]:
    print("   ", d, "OK" if d.exists() else "MISSING")

# 4. Перевірка root wrapper
if WRAPPER.exists():
    print("[4] Wrapper exists:", WRAPPER)
else:
    print("[4] Wrapper MISSING:", WRAPPER)
    sys.exit(1)

# 5. Перевірка root helper
if ROOT_HELPER.exists():
    print("[5] Root helper exists:", ROOT_HELPER)
else:
    print("[5] Root helper MISSING:", ROOT_HELPER)
    sys.exit(1)

# 6. Пробний запуск root-helper (dry-run)
print("[6] Testing root helper via pkexec…")

dry_cmd = ["pkexec", str(ROOT_HELPER), "--dry"]

try:
    out = subprocess.check_output(dry_cmd, stderr=subprocess.STDOUT, text=True, timeout=5)
    print("[6] pkexec OK: root helper executed")
    print(out.split("\n")[0])
except subprocess.CalledProcessError as e:
    print("[6] pkexec ERROR:\n", e.output)
except Exception as e:
    print("[6] ERROR:", e)

# 7. Перевірка доступних дисків
print("[7] Listing physical disks…")

try:
    out = subprocess.check_output(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT"], text=True)
    print(out)
except Exception as e:
    print("[7] lsblk ERROR:", e)

# 8. Створення тестового запису в results
print("[8] Writing test result file…")
test_file = RESULTS / "selftest_ok.txt"

try:
    test_file.write_text("SELFTEST_OK")
    print("[8] OK: wrote to", test_file)
except Exception as e:
    print("[8] ERROR writing:", e)
    sys.exit(1)

# 9. Перевірка progress-bar callback
print("[9] Testing fake progress updates…")

def fake_progress():
    for i in range(0, 101, 25):
        print(f"    Progress: {i}%")
        time.sleep(0.1)

try:
    fake_progress()
    print("[9] Progress bar simulation OK")
except Exception as e:
    print("[9] ERROR:", e)

print("\n=== SELF-TEST COMPLETE ===")
