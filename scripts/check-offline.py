#!/usr/bin/env python3
"""Validate effective Compose defaults without Docker daemon access or PyYAML."""
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICIES = {
    "zk": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "kraft": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "epc": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "monitoring": {
        "grafana": {
            "GF_ANALYTICS_REPORTING_ENABLED": "false",
            "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
            "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
            "GF_PLUGINS_PREINSTALL_DISABLED": "true",
            "GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED": "true",
            "GF_PLUGINS_PLUGIN_ADMIN_ENABLED": "false",
            "GF_SECURITY_DISABLE_GRAVATAR": "true",
            "GF_SNAPSHOTS_EXTERNAL_ENABLED": "false",
        }
    },
}


def violations(variant, config):
    errors = []
    for service, policy in POLICIES[variant].items():
        env = config.get("services", {}).get(service, {}).get("environment", {})
        for key, expected in policy.items():
            actual = env.get(key)
            if actual != expected:
                errors.append(f"{variant}/{service}: {key} must be {expected}; got {actual!r}")
    return errors


def main():
    errors = []
    for variant in POLICIES:
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(ROOT / variant / ".env.template"),
             "-f", str(ROOT / variant / "docker-compose.yml"), "config", "--format", "json"],
            cwd=ROOT, text=True, capture_output=True,
        )
        if result.returncode:
            # Do not dump rendered configuration, which could contain secrets.
            errors.append(f"{variant}: Compose rendering failed; run make compose-check")
            continue
        errors.extend(violations(variant, json.loads(result.stdout)))
    if errors:
        print("Offline policy check failed:\n" + "\n".join(errors), file=sys.stderr)
        return 1
    print("Offline defaults verified: all Kafbat variants and shared Grafana.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
