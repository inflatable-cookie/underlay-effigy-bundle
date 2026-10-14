"""Compile touched profile code without creating bytecode/build artifacts."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
for relative in ("scripts/dev/profile_launcher.py", "scripts/dev/port_inventory.py", "scripts/dev/port_inventory_test.py", "scripts/dev/silo_client.py", "scripts/dev/storage_launcher.py", "scripts/dev/silo_bootstrap_test.py", "scripts/dev/profile_admission_test.py",
                 "scripts/auth_operation.py", "scripts/auth_operation_test.py", "scripts/reference_storage_probe.py", "scripts/qualify-auth-cpu.py", "scripts/auth_cpu_inputs.py", "scripts/auth_cpu_test.py", "scripts/qualify-dev-profiles.py", "scripts/qualify-profile-preconditions.py", "scripts/qualify-reference-container.py", "scripts/qualify-reference-optin.py", "scripts/qualify-reference-runtime.py", "scripts/qualify-reference-profiles.py",
                 "scripts/pending_start_identity.py", "scripts/qualification/managed-listener-probe.py",
                 "scripts/listener_snapshot.py", "scripts/transition_snapshot.py", "scripts/qualification_runtime.py", "scripts/reference_lifecycle_test.py",
                 "scripts/qualification/formatter_cases.py", "scripts/formatter_provenance.py", "scripts/formatter_provenance_test.py", "scripts/silo_fixture.py", "scripts/service_defaults.py", "scripts/routing_guard.py", "scripts/routing_guard_test.py", "scripts/storage_correlation.py", "scripts/storage_correlation_test.py", "scripts/qualify-storage-correlation.py"):
    compile((root / relative).read_text(), relative, "exec")
for relative in ("scripts/dev/managed-vite-listener.mjs", "scripts/dev/context-diagnostic.mjs",
                 "scripts/dev/profile-admission.test.mjs"):
    subprocess.run(["node", "--check", str(root / relative)], check=True, timeout=30)
print("PASS profile Python/JavaScript syntax compilation")
