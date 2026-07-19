"""One-shot, low-frequency, harmless readiness retest for CVE-2020-11978.

Defensive verification only: brings up the local Vulhub Airflow stack via the
real orchestrator (init-service-first + target-service health filtering), does a
single readiness check on the webserver entry point, then force-reclaims the
independent Compose project (containers, networks, volumes) no matter what.

No PoC payload, no exploit request, no outbound target traffic.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cve_hunter import agents

COMPOSE = Path("third_party/vulhub/airflow/CVE-2020-11978/docker-compose.yml").resolve()
PROJECT = "cvehunter-airflowdiag-0718b"


def _hard_cleanup(reason: str) -> None:
    command = agents._docker_compose_command()
    if not command or not COMPOSE.is_file():
        return
    print(f"[hard-cleanup] {reason}")
    result = agents._cleanup_compose_project(command, COMPOSE, PROJECT)
    print(f"[hard-cleanup] success={result['success']} rc={result['returncode']}")


def main() -> int:
    if not COMPOSE.is_file():
        print(f"compose not found: {COMPOSE}")
        return 2

    target_url = agents._guess_target_url_from_compose(COMPOSE)
    print(f"[retest] compose={COMPOSE}")
    print(f"[retest] target_url={target_url} project={PROJECT}")

    candidate = {
        "compose_file": str(COMPOSE),
        "target_url": target_url,
        "compose_project_name": PROJECT,
    }

    setup: dict = {}
    try:
        setup = agents._start_compose_environment(candidate)
        print("[retest] success:", setup.get("success"))
        init = setup.get("initialization") or {}
        if init:
            print("[retest] init.success:", init.get("success"))
            print("[retest] init.status:", json.dumps(init.get("service_status", {}), ensure_ascii=False))
        health = setup.get("healthcheck") or {}
        print("[retest] health.type:", health.get("type"))
        print("[retest] health.success:", health.get("success"))
        print("[retest] health.services:", health.get("services"))
        print("[retest] health.observed:", health.get("observed_services"))
        print("[retest] health.service_health:", json.dumps(health.get("service_health", {}), ensure_ascii=False))
        if not setup.get("success"):
            print("[retest] error:", setup.get("error"))
    finally:
        environment = {
            "launcher": "docker_compose",
            "setup_mode": "docker_compose",
            "compose_file": str(COMPOSE),
            "setup_result": setup if isinstance(setup, dict) else {},
        }
        if isinstance(setup, dict) and setup.get("started_by_orchestrator"):
            teardown = agents.teardown_environment(environment)
            print("[retest] teardown.success:", teardown.get("success"), "skipped:", teardown.get("skipped"))
            if not teardown.get("success") and not teardown.get("skipped"):
                _hard_cleanup("orchestrator teardown reported failure")
        else:
            _hard_cleanup("setup did not report ownership; ensuring no residue")

    return 0 if setup.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
