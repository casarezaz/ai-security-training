#!/usr/bin/env python3
"""
Verify that security tools are installed in the correct locations.
Run from either conda env to check its packages,
or without an env to check Docker tools.
"""
import sys
import os
import subprocess
import shutil

def check_python(module, name):
    try:
        __import__(module)
        return True, f"  ✅  {name:<40} OK"
    except ImportError:
        return False, f"  ❌  {name:<40} NOT FOUND"

def check_docker_tool(tool):
    try:
        result = subprocess.run(
            ["docker", "exec", "aiml-sectools", "which", tool],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"  ✅  {tool:<40} OK (Docker)"
        return False, f"  ❌  {tool:<40} NOT IN CONTAINER"
    except Exception:
        return False, f"  ❌  {tool:<40} CONTAINER NOT RUNNING"

def check_command(cmd, name):
    if shutil.which(cmd):
        return True, f"  ✅  {name:<40} OK"
    return False, f"  ❌  {name:<40} NOT FOUND"

def check_file(path, name, perms=None):
    expanded = os.path.expanduser(path)
    if os.path.exists(expanded):
        if perms:
            actual = oct(os.stat(expanded).st_mode)[-3:]
            if actual == perms:
                return True, f"  ✅  {name:<40} OK (perms: {actual})"
            else:
                return False, f"  ⚠️  {name:<40} EXISTS (perms: {actual}, expected {perms})"
        return True, f"  ✅  {name:<40} OK"
    return False, f"  ❌  {name:<40} NOT FOUND"

print("=" * 60)
print("  Security Tool Verification")
print("=" * 60)

env = os.environ.get("CONDA_DEFAULT_ENV", "none")
print(f"\n  Active conda env: {env}")

passed = failed = 0

# Check based on which env is active
if env == "aiml-cyber":
    print("\n  --- ML/DL Environment (aiml-cyber) ---")
    ml_tools = {
        "numpy": "NumPy", "pandas": "Pandas", "sklearn": "scikit-learn",
        "xgboost": "XGBoost", "torch": "PyTorch", "tensorflow": "TensorFlow",
        "transformers": "Transformers", "spacy": "spaCy",
    }
    for mod, name in ml_tools.items():
        ok, msg = check_python(mod, name)
        print(msg)
        passed += ok; failed += (not ok)

elif env == "aiml-sectools":
    print("\n  --- Security Environment (aiml-sectools) ---")
    sec_tools = {
        "art": "ART (Adversarial Robustness Toolbox)",
        "foolbox": "Foolbox",
        "stix2": "STIX 2.1",
        "mitre_attack_data": "MITRE ATT&CK",
        "sigma": "pySigma",
        "OTXv2": "AlienVault OTX",
        "vt": "VirusTotal",
        "shodan": "Shodan",
        "opacus": "Opacus (DP-SGD)",
        "networkx": "NetworkX",
        "neo4j": "Neo4j driver",
        "shap": "SHAP",
    }
    for mod, name in sec_tools.items():
        ok, msg = check_python(mod, name)
        print(msg)
        passed += ok; failed += (not ok)

# Docker tools (check regardless of env)
print("\n  --- Docker Container Tools ---")
docker_tools = ["nmap", "tshark", "tcpdump", "yara", "ssdeep", "python3"]
for tool in docker_tools:
    ok, msg = check_docker_tool(tool)
    print(msg)
    passed += ok; failed += (not ok)

# Wrapper scripts
print("\n  --- Wrapper Scripts ---")
wrapper_dir = os.path.expanduser("~/aiml-cybersecurity/scripts/wrappers")
wrappers = ["nmap", "tshark", "tcpdump", "yara", "ssdeep", "secshell"]
for w in wrappers:
    path = os.path.join(wrapper_dir, w)
    if os.path.isfile(path) and os.access(path, os.X_OK):
        print(f"  ✅  {w:<40} OK")
        passed += 1
    else:
        print(f"  ❌  {w:<40} NOT FOUND")
        failed += 1

# ─────────────────────────────────────────────────────────────────────────────
# macOS Hardening & Monitoring Tools
# ─────────────────────────────────────────────────────────────────────────────
print("\n  --- macOS Hardening Scripts ---")
project = os.path.expanduser("~/aiml-cybersecurity")
scripts = {
    f"{project}/harden_macos.sh": "harden_macos.sh",
    f"{project}/scripts/file_integrity.sh": "file_integrity.sh",
    f"{project}/scripts/security_monitor.sh": "security_monitor.sh",
    f"{project}/scripts/system_audit.sh": "system_audit.sh",
    f"{project}/scripts/image_scanner.sh": "image_scanner.sh",
}
for path, name in scripts.items():
    if os.path.isfile(path) and os.access(path, os.X_OK):
        print(f"  ✅  {name:<40} OK")
        passed += 1
    else:
        print(f"  ❌  {name:<40} NOT FOUND/NOT EXECUTABLE")
        failed += 1

print("\n  --- File Integrity Baseline ---")
baseline = os.path.expanduser("~/aiml-cybersecurity/reports/security/file_integrity_baseline.txt")
ok_b, msg_b = check_file(baseline, "Integrity baseline", "600")
print(msg_b)
passed += ok_b; failed += (not ok_b)

print("\n  --- LaunchD Agent ---")
plist = os.path.expanduser("~/Library/LaunchAgents/com.aiml-cybersecurity.daily-scan.plist")
ok_p, msg_p = check_file(plist, "Daily scan plist")
print(msg_p)
passed += ok_p; failed += (not ok_p)

# Check if launchd agent is loaded
try:
    result = subprocess.run(
        ["launchctl", "list"], capture_output=True, text=True, timeout=5
    )
    if "aiml-cybersecurity" in result.stdout:
        print(f"  ✅  {'LaunchD agent loaded':<40} OK")
        passed += 1
    else:
        print(f"  ⚠️  {'LaunchD agent loaded':<40} NOT LOADED (run: launchctl load ~/Library/LaunchAgents/com.aiml-cybersecurity.daily-scan.plist)")
        failed += 1
except Exception:
    print(f"  ❌  {'LaunchD check':<40} COULD NOT VERIFY")
    failed += 1

print("\n  --- Image Scanner ---")
ok_t, msg_t = check_command("trivy", "Trivy (image scanner)")
print(msg_t)
passed += ok_t; failed += (not ok_t)

print(f"\n  Results: {passed} passed, {failed} failed")
print("=" * 60)
sys.exit(1 if failed > 5 else 0)
