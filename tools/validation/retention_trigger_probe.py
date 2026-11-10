#!/usr/bin/env python3
"""No-model native probe for the 0.17.2 default-automatic maintenance path.

Verifies, on the running host, that the SessionEnd background trigger
works without any model, login, trust or Codex binary:

  S1  parent-exit survival and the full automatic chain: an ordinary
      SessionEnd hook invocation (whose process exits immediately)
      dispatches one detached maintenance child that materializes the
      default policy and quarantines an expired fixture session.
  S2  quarantine grace expiry advances to a real purge on later trigger
      passes (tombstone written, record retired) without any user action.
  S3  concurrent SessionEnd dispatches are deduplicated (one claim, one
      quarantine, no double maintenance).
  S4  the durable opt-out skips the trigger (no dispatch, no deletion).
  S5  a corrupted policy never authorizes cleanup (skip recorded, data
      preserved).
  S6  the SessionEnd hook wall time (including the trigger decision and
      detached spawn) stays inside the 3 s host budget.
  S7  a claim stranded past its TTL is recovered by the next SessionEnd.

Every scenario runs the REAL product entry (``scripts/cg_hook.py``) and
the REAL detached spawn seam against real filesystem fixtures under a
temporary data root; nothing outside the probe work directory is touched.
The probe is the per-platform evidence source for the trigger: macOS and
Windows each run it natively; neither run substitutes for the other.

Usage:
    python tools/validation/retention_trigger_probe.py \
        --work-dir <empty-dir-outside-the-repo> [--scripts-dir <scripts>] \
        [--json-out <path>] [--keep-on-fail]

Exit code 0 iff every scenario passed on this platform.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SESSION_END_HOST_BUDGET_SECONDS = 3.0
POLL_TIMEOUT_SECONDS = 120.0
POLL_INTERVAL_SECONDS = 0.25


def log(message: str) -> None:
    print(message.encode("ascii", "backslashreplace").decode("ascii"), flush=True)


def load_module(path: Path, name: str):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Probe:
    def __init__(self, scripts_dir: Path, work_dir: Path) -> None:
        self.scripts_dir = scripts_dir
        self.work_dir = work_dir
        self.cg = load_module(scripts_dir / "context_guard.py",
                              "cg_retention_trigger_probe")
        self.hook = scripts_dir / "cg_hook.py"
        self.results: list[dict] = []

    # ---- fixture helpers -------------------------------------------------

    def new_root(self, name: str) -> tuple[Path, Path]:
        root = self.work_dir / name
        # Scenario roots never carry state across probe runs: stale trigger
        # records or fixtures from an earlier attempt would corrupt the
        # observations this probe is the evidence source for.
        shutil.rmtree(root, ignore_errors=True)
        data = root / "guard-data"
        project = root / "project"
        project.mkdir(parents=True, exist_ok=True)
        return data, project

    def make_expired_session(self, data: Path, project: Path, name: str,
                             *, ended_days_ago: float = 45.0) -> str:
        encoded = self.cg.safe_session_id(name)
        payload = {"hook_event_name": "UserPromptSubmit", "session_id": name,
                   "cwd": str(project), "prompt": "probe fixture", "turn_id": "t1"}
        # In-process fixture writes must target THIS probe root only: the
        # data-dir environment is set for the dispatch and restored after,
        # and the trigger is disabled so fixtures never spawn children.
        marker = "CONTEXT_GUARD_DATA_DIR"
        saved = os.environ.get(marker)
        try:
            os.environ[marker] = str(data)
            os.environ["CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER"] = "1"
            self.cg.dispatch(payload)
        finally:
            if saved is None:
                os.environ.pop(marker, None)
            else:
                os.environ[marker] = saved
        state_path = data / "sessions-v2" / encoded / "state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        for item in state.get("requirements", []):
            item["status"] = "pass"
        for item in state.get("acceptance_items", []):
            item["status"] = "pass"
        for unit in state.get("work_units", []):
            unit["status"] = "completed"
            unit["closed_at"] = self.cg.utc_now()
        state["open_items"] = []
        state["wait_conditions"] = []
        state["session"]["ended_at"] = (
            self.cg.dt.datetime.now(self.cg.dt.timezone.utc)
            - self.cg.dt.timedelta(days=ended_days_ago)
        ).isoformat().replace("+00:00", "Z")
        state["content_hash"] = self.cg.state_content_hash(state)
        state_path.write_text(json.dumps(state, ensure_ascii=False) + "\n",
                              encoding="utf-8")
        return encoded

    def session_dir(self, data: Path, encoded: str) -> Path:
        return data / "sessions-v2" / encoded

    def hook_env(self, data: Path) -> dict:
        env = dict(os.environ)
        env["CONTEXT_GUARD_DATA_DIR"] = str(data)
        env["CONTEXT_GUARD_DISABLE_RETENTION_TRIGGER"] = ""
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.pop("PYTHONPATH", None)
        return env

    def run_session_end_hook(self, data: Path, project: Path, session: str,
                             *, expect_exit: int = 0) -> tuple[float, int]:
        payload = {"hook_event_name": "SessionEnd", "session_id": session,
                   "cwd": str(project)}
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-B", str(self.hook)],
            input=json.dumps(payload).encode("utf-8"),
            env=self.hook_env(data), capture_output=True, timeout=60)
        elapsed = time.monotonic() - started
        if proc.returncode != expect_exit:
            raise RuntimeError(
                f"hook exit {proc.returncode} (expected {expect_exit}): "
                f"{proc.stderr.decode('utf-8', 'backslashreplace')[:300]}")
        return elapsed, proc.returncode

    def trigger_state(self, data: Path) -> dict:
        path = data / "sessions-v2" / ".locks" / self.cg.RETENTION_TRIGGER_STATE_NAME
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return value if isinstance(value, dict) else {}

    def backdate_last_attempt(self, data: Path, hours: float) -> None:
        path = (data / "sessions-v2" / ".locks"
                / self.cg.RETENTION_TRIGGER_STATE_NAME)
        state = self.trigger_state(data)
        state["schema"] = self.cg.RETENTION_TRIGGER_STATE_SCHEMA
        state["updated_at"] = self.cg.utc_now()
        state["last_attempt_at"] = (
            self.cg.dt.datetime.now(self.cg.dt.timezone.utc)
            - self.cg.dt.timedelta(hours=hours)
        ).isoformat().replace("+00:00", "Z")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state) + "\n", encoding="utf-8")

    def await_success(self, data: Path, *, timeout: float,
                      after: str | None = None) -> dict:
        """Wait for a trigger success strictly NEWER than ``after`` (an
        earlier pass's recorded success is not evidence for this one)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.trigger_state(data)
            success = state.get("last_success_at")
            if success and (after is None or success > after):
                return state
            time.sleep(POLL_INTERVAL_SECONDS)
        raise RuntimeError(
            f"trigger success not observed within {timeout}s "
            f"(after={after!r}); state: "
            f"{json.dumps(self.trigger_state(data))[:400]}")

    def record(self, scenario: str, ok: bool, detail: dict) -> None:
        entry = {"scenario": scenario, "result": "pass" if ok else "fail",
                 **detail}
        self.results.append(entry)
        log(f"[{'PASS' if ok else 'FAIL'}] {scenario}: "
            + json.dumps(detail, ensure_ascii=False, sort_keys=True)[:600])

    # ---- scenarios -------------------------------------------------------

    def s1_parent_exit_survival(self) -> None:
        data, project = self.new_root("s1")
        encoded = self.make_expired_session(data, project, "expired-45d")
        fresh = self.make_expired_session(data, project, "fresh-2d",
                                          ended_days_ago=2.0)
        elapsed, _ = self.run_session_end_hook(data, project, "current-probe")
        state = self.await_success(data, timeout=POLL_TIMEOUT_SECONDS)
        quarantined = not self.session_dir(data, encoded).exists()
        fresh_kept = self.session_dir(data, fresh).exists()
        policy = json.loads(
            (data / "sessions-v2" / ".locks" / self.cg.RETENTION_POLICY_NAME)
            .read_text(encoding="utf-8"))
        ok = (quarantined and fresh_kept
              and policy.get("policy_source") == "default_auto"
              and policy.get("enabled") is True)
        self.record("S1_parent_exit_survival_default_auto_chain", ok, {
            "hook_seconds": round(elapsed, 3),
            "expired_quarantined": quarantined, "fresh_kept": fresh_kept,
            "policy_source": policy.get("policy_source"),
            "last_success_at": state.get("last_success_at"),
            "platform": sys.platform,
        })
        return data, project

    def s2_purge_after_grace(self, data: Path, project: Path) -> None:
        qdir = data / "sessions-v2" / ".locks" / "retention-quarantine"
        records = list(qdir.glob("*.record.json"))
        if len(records) != 1:
            raise RuntimeError(f"expected one quarantine record, found {len(records)}")
        record = json.loads(records[0].read_text(encoding="utf-8"))
        record["quarantined_at"] = (
            self.cg.dt.datetime.now(self.cg.dt.timezone.utc)
            - self.cg.dt.timedelta(
                days=int(record.get("quarantine_days") or 7) + 2)
        ).isoformat().replace("+00:00", "Z")
        records[0].write_text(json.dumps(record) + "\n", encoding="utf-8")
        # The minimum interval is a fairness guard; backdate the recorded
        # attempt so the probe's next ordinary SessionEnd dispatches again.
        self.backdate_last_attempt(data, hours=8)
        previous_success = self.trigger_state(data).get("last_success_at")
        self.run_session_end_hook(data, project, "current-probe")
        state = self.await_success(data, timeout=POLL_TIMEOUT_SECONDS,
                                   after=previous_success)
        tombstones = list(qdir.glob("*.tombstone.json"))
        record_gone = not records[0].exists()
        purged = (state.get("last_outcome", {}).get("purge") or {}).get("purged", 0)
        ok = record_gone and len(tombstones) == 1 and purged >= 1
        self.record("S2_purge_advances_after_quarantine_grace", ok, {
            "record_retired": record_gone, "tombstones": len(tombstones),
            "purged": purged, "platform": sys.platform,
        })

    def s3_concurrent_dispatch_deduplicated(self) -> None:
        data, project = self.new_root("s3")
        encoded = self.make_expired_session(data, project, "expired-45d")
        payload = json.dumps({"hook_event_name": "SessionEnd",
                              "session_id": "current-probe",
                              "cwd": str(project)}).encode()
        env = self.hook_env(data)
        procs = [subprocess.Popen(
            [sys.executable, "-B", str(self.hook)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            for _ in range(2)]
        for proc in procs:
            proc.communicate(payload, timeout=60)
        claims = list((data / "sessions-v2" / ".locks")
                      .glob(self.cg._RETENTION_TRIGGER_CLAIM_NAME))
        state = self.await_success(data, timeout=POLL_TIMEOUT_SECONDS)
        # Exactly one quarantine even though both hooks fired.
        qdir = data / "sessions-v2" / ".locks" / "retention-quarantine"
        record_count = len(list(qdir.glob("*.record.json")))
        # One dispatch: one quarantine record, no recorded claim race, and
        # the dispatch claim released after the single child settled.
        last_skip = (state.get("last_skip") or {}).get("reason")
        claim_released = not (data / "sessions-v2" / ".locks"
                              / self.cg._RETENTION_TRIGGER_CLAIM_NAME).exists()
        ok = (record_count == 1 and not self.session_dir(data, encoded).exists()
              and claim_released and last_skip != "claim_race")
        self.record("S3_concurrent_dispatch_deduplicated", ok, {
            "quarantine_records": record_count,
            "claim_released": claim_released,
            "last_skip": last_skip,
            "live_claims_after_settle": len(claims),
            "last_success_at": state.get("last_success_at"),
            "platform": sys.platform,
        })

    def s4_opt_out_skips(self) -> None:
        data, project = self.new_root("s4")
        encoded = self.make_expired_session(data, project, "expired-45d")
        proc = subprocess.run(
            [sys.executable, "-B", str(self.scripts_dir / "context_guard.py"),
             "cleanup", "--data-dir", str(data), "--policy", "disable"],
            env=self.hook_env(data), text=True, capture_output=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(f"policy disable failed: {proc.stderr[:300]}")
        self.run_session_end_hook(data, project, "current-probe")
        time.sleep(2.0)  # a dispatch would record success quickly; allow slack
        state = self.trigger_state(data)
        kept = self.session_dir(data, encoded).exists()
        optout = self.cg._retention_read_optout(data)
        ok = (kept and not state.get("last_success_at")
              and state.get("last_skip", {}).get("reason") == "opt_out"
              and isinstance(optout, dict)
              and optout.get("reason") == "policy-disable")
        self.record("S4_durable_opt_out_skips_trigger", ok, {
            "session_kept": kept, "skip_reason":
                state.get("last_skip", {}).get("reason"),
            "optout_reason": (optout or {}).get("reason")
            if isinstance(optout, dict) else str(optout),
            "platform": sys.platform,
        })

    def s5_corrupted_policy_never_cleans(self) -> None:
        data, project = self.new_root("s5")
        encoded = self.make_expired_session(data, project, "expired-45d")
        policy_path = data / "sessions-v2" / ".locks" / self.cg.RETENTION_POLICY_NAME
        policy_path.write_text("{corrupted-by-probe", encoding="utf-8")
        self.run_session_end_hook(data, project, "current-probe")
        time.sleep(2.0)
        state = self.trigger_state(data)
        kept = self.session_dir(data, encoded).exists()
        ok = (kept
              and state.get("last_skip", {}).get("reason") == "policy_invalid"
              and not state.get("last_success_at"))
        self.record("S5_corrupted_policy_never_authorizes_cleanup", ok, {
            "session_kept": kept, "skip_reason":
                state.get("last_skip", {}).get("reason"),
            "skip_detail": state.get("last_skip", {}).get("detail"),
            "platform": sys.platform,
        })

    def s6_hook_latency_within_budget(self) -> None:
        """Three trigger generations, each PROVEN: the previous worker's
        claim released, a strictly newer attempt/dispatch recorded, and a
        strictly newer worker completion observed -- with the Hook wall
        time measured per iteration inside the 3 s budget."""
        data, project = self.new_root("s6")
        self.make_expired_session(data, project, "expired-45d")
        claim = (data / "sessions-v2" / ".locks"
                 / self.cg._RETENTION_TRIGGER_CLAIM_NAME)
        worst = 0.0
        dispatches = 0
        previous_success = None
        for index in range(3):
            deadline = time.monotonic() + 60
            while claim.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"iteration {index}: previous claim never released")
                time.sleep(POLL_INTERVAL_SECONDS)
            self.backdate_last_attempt(data, hours=8)
            pre = self.trigger_state(data)
            elapsed, _ = self.run_session_end_hook(
                data, project, "current-probe")
            post = self.trigger_state(data)
            if (not post.get("last_attempt_at")
                    or post.get("last_attempt_at") == pre.get("last_attempt_at")):
                raise RuntimeError(
                    f"iteration {index}: no new dispatch recorded")
            dispatches += 1
            self.await_success(data, timeout=POLL_TIMEOUT_SECONDS,
                               after=previous_success)
            previous_success = self.trigger_state(data).get("last_success_at")
            worst = max(worst, elapsed)
        ok = worst < SESSION_END_HOST_BUDGET_SECONDS and dispatches == 3
        self.record("S6_session_end_hook_latency_including_trigger", ok, {
            "worst_hook_seconds": round(worst, 3),
            "host_budget_seconds": SESSION_END_HOST_BUDGET_SECONDS,
            "iterations": 3,
            "dispatches_proven": dispatches,
            "platform": sys.platform,
        })

    def s7_stale_claim_recovered(self) -> None:
        data, project = self.new_root("s7")
        encoded = self.make_expired_session(data, project, "expired-45d")
        claim = data / "sessions-v2" / ".locks" / self.cg._RETENTION_TRIGGER_CLAIM_NAME
        claim.parent.mkdir(parents=True, exist_ok=True)
        claim.write_text("{}\n", encoding="utf-8")
        old = time.time() - (self.cg._RETENTION_TRIGGER_CLAIM_TTL_SECONDS + 120)
        os.utime(claim, (old, old))
        self.run_session_end_hook(data, project, "current-probe")
        state = self.await_success(data, timeout=POLL_TIMEOUT_SECONDS)
        ok = (not self.session_dir(data, encoded).exists()
              and not claim.exists())
        self.record("S7_stale_claim_recovered_by_next_session_end", ok, {
            "quarantined": not self.session_dir(data, encoded).exists(),
            "claim_released": not claim.exists(),
            "last_success_at": state.get("last_success_at"),
            "platform": sys.platform,
        })

    # ---- driver ----------------------------------------------------------

    def run(self, keep_on_fail: bool = False) -> int:
        started = time.monotonic()
        failed = False
        try:
            result = self.s1_parent_exit_survival()
            data, project = (result if isinstance(result, tuple)
                             else (None, None))
            if data is not None:
                self.s2_purge_after_grace(data, project)
        except Exception as exc:  # noqa: BLE001 - probe records, never crashes
            failed = True
            self.record("S1S2_chain", False,
                        {"error": repr(exc)[:400], "platform": sys.platform})
            if not keep_on_fail:
                failed = True
        for scenario in (self.s3_concurrent_dispatch_deduplicated,
                         self.s4_opt_out_skips,
                         self.s5_corrupted_policy_never_cleans,
                         self.s6_hook_latency_within_budget,
                         self.s7_stale_claim_recovered):
            if failed and not keep_on_fail:
                break
            try:
                scenario()
            except Exception as exc:  # noqa: BLE001
                failed = True
                self.record(scenario.__name__, False,
                            {"error": repr(exc)[:400], "platform": sys.platform})
        ok = (not failed and self.results
              and all(entry["result"] == "pass" for entry in self.results))
        report = {
            "probe": "retention-trigger/v1",
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "results": self.results,
            "accepted": ok,
        }
        return 0 if ok else 1, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts-dir", type=Path,
                        default=REPO / "scripts")
    parser.add_argument("--work-dir", type=Path, required=True,
                        help="empty output directory OUTSIDE the repository")
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--keep-on-fail", action="store_true",
                        help="run remaining scenarios after a failure")
    args = parser.parse_args()
    if not args.scripts_dir.is_dir():
        parser.error(f"--scripts-dir not found: {args.scripts_dir}")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    probe = Probe(args.scripts_dir.resolve(), args.work_dir.resolve())
    code, report = probe.run(keep_on_fail=args.keep_on_fail)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
    log(f"probe {'ACCEPTED' if report['accepted'] else 'REFUSED'} "
        f"({report['elapsed_seconds']}s, {sys.platform})")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
