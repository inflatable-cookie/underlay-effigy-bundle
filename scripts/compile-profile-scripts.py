"""Compile touched profile code without creating bytecode/build artifacts."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
for relative in ("scripts/dev/profile_launcher.py", "scripts/dev/profile_admission_test.py",
                 "scripts/qualify-reference-optin.py", "scripts/reference_lifecycle_test.py"):
    compile((root / relative).read_text(), relative, "exec")
for relative in ("scripts/dev/managed-vite-listener.mjs", "scripts/dev/context-diagnostic.mjs",
                 "scripts/dev/profile-admission.test.mjs"):
    subprocess.run(["node", "--check", str(root / relative)], check=True, timeout=30)
print("PASS profile Python/JavaScript syntax compilation")
