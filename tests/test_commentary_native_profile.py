"""Fail-closed raw-input checks for the zero-model commentary profile."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock

from tools.validation import commentary_native_profile as profile


class CommentaryNativeProfileTests(unittest.TestCase):
    def symlink_or_skip(self, link, target):
        try:
            link.symlink_to(target)
        except OSError as exc:
            if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows host lacks symbolic-link privilege")
            raise

    def test_codex_version_comes_from_official_initialize_not_reviewer_policy(self):
        self.assertEqual(profile._official_codex_version(
            {"codexHome": "/isolated", "userAgent":
             "Codex Desktop/0.153.4 (Mac OS; arm64)"}, "/isolated"), "0.153.4")
        self.assertEqual(profile._official_codex_version(
            {"codexHome": "/isolated", "userAgent":
             "cg142-independent-review"}, "/isolated"), "unknown")
        with self.assertRaises(profile.ReplayError):
            profile._official_codex_version(
                {"codexHome": "/other", "userAgent": "Codex/0.153.4"},
                "/isolated")

    def test_owned_cleanup_requires_original_collector_shape_and_all_positive_facts(self):
        root = Path(__file__).resolve().parents[1]
        process_tree = root / "scripts/cg_process_tree.py"
        source = {"scripts/cg_process_tree.py":
                  hashlib.sha256(process_tree.read_bytes()).hexdigest()}
        result = {"status": "source_chain_observed",
                  "phase": "offline_chain_checked",
                  "cleanup": {"owned_process_exited": True,
                              "process_group_kill_attempted": True,
                              "process_group_cleanup_error": None,
                              "owned_tree_empty": True,
                              "owned_tree_no_running_members": True,
                              "process_group_absent": True,
                              "process_group_signal_denied": False,
                              "process_group_query_denied": False,
                              "escaped_descendants": "not_established"}}
        profile._verify_owned_cleanup(result, "linux", source, root)
        for field, value in (("owned_tree_empty", False),
                             ("process_group_cleanup_error", "denied"),
                             ("escaped_descendants", "passed")):
            changed = deepcopy(result)
            changed["cleanup"][field] = value
            with self.subTest(field=field), self.assertRaises(profile.ReplayError):
                profile._verify_owned_cleanup(changed, "linux", source, root)
        windows = deepcopy(result)
        windows["cleanup"]["process_group_absent"] = None
        profile._verify_owned_cleanup(windows, "windows", source, root)
        with self.assertRaises(profile.ReplayError):
            profile._verify_owned_cleanup(windows, "linux", source, root)
        with self.assertRaises(profile.ReplayError):
            profile._verify_owned_cleanup(result, "windows", source, root)
        with self.assertRaises(profile.ReplayError):
            profile._verify_owned_cleanup(windows, "windows", {}, root)
        for field, value in (("owned_tree_empty", False),
                             ("owned_tree_no_running_members", False),
                             ("process_group_cleanup_error", "job_query_denied"),
                             ("process_group_query_denied", True)):
            changed = deepcopy(windows)
            changed["cleanup"][field] = value
            with self.subTest(field=field), self.assertRaises(profile.ReplayError):
                profile._verify_owned_cleanup(changed, "windows", source, root)

    def test_official_host_os_requires_matching_server_identity(self):
        for agent, host in (("Codex/0.153.4 (Windows; x86_64)", "windows"),
                            ("Codex Desktop/0.153.4 (Mac OS; arm64)", "darwin"),
                            ("Codex/0.153.4 (Linux; x86_64)", "linux")):
            self.assertEqual(profile._official_host_os({"userAgent": agent}, host), host)
        for agent, host in (("Codex/0.153.4 (Windows; x86_64)", "linux"),
                            ("Codex/0.153.4", "windows"),
                            ("Codex/0.153.4 (Windows; Linux)", "windows")):
            with self.assertRaises(profile.ReplayError):
                profile._official_host_os({"userAgent": agent}, host)

    def test_checkout_projection_binds_original_disk_bytes_to_exact_git_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True,
                           capture_output=True)
            blob = b"one\ntwo\n"
            converted = blob.replace(b"\n", b"\r\n")
            (root / "converted.txt").write_bytes(blob)
            (root / "plain.txt").write_bytes(b"unchanged\n")
            subprocess.run(["git", "-C", str(root), "-c", "core.autocrlf=false",
                            "add", "converted.txt", "plain.txt"], check=True,
                           capture_output=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Codex",
                            "-c", "user.email=12345+codex@users.noreply.github.com",
                            "commit", "-qm", "fixture"], check=True,
                           capture_output=True)
            commit = subprocess.check_output(["git", "-C", str(root),
                                              "rev-parse", "HEAD"], text=True).strip()
            (root / "converted.txt").write_bytes(converted)
            files = {"converted.txt": profile._digest(converted),
                     "plain.txt": profile._digest(b"unchanged\n")}
            manifest = {"original_source_commit": commit,
                        "source_manifest": {"sha256": "a" * 64}}
            plan = {"harness_root": str(root),
                    "source_tree_sha256": profile._digest(profile.fixture.canonical(files))}
            proof = {"schema": profile.PROJECTION_SCHEMA, "source_commit": commit,
                     "source_manifest_sha256": "a" * 64,
                     "source_tree_sha256": plan["source_tree_sha256"],
                     "files": {"converted.txt": {
                         "conversion": "lf_to_crlf_exact",
                         "blob_sha256": profile._digest(blob),
                         "disk_sha256": profile._digest(converted),
                         "blob_bytes": len(blob), "disk_bytes": len(converted)}}}
            allowed = frozenset({"converted.txt"})
            profile._verify_checkout_source(manifest, plan, files, proof, root, allowed)
            with self.assertRaises(profile.ReplayError):
                profile._verify_checkout_source(manifest, plan, files, None, root, allowed)
            for mutate in (
                lambda p: p.update(source_commit="0" * 40),
                lambda p: p.update(source_manifest_sha256="b" * 64),
                lambda p: p["files"]["converted.txt"].update(blob_sha256="0" * 64),
                lambda p: p["files"]["converted.txt"].update(disk_bytes=99),
                lambda p: p["files"]["converted.txt"].update(conversion="normalize"),
                lambda p: p["files"].update({"../outside": deepcopy(
                    p["files"]["converted.txt"])}),
            ):
                changed = deepcopy(proof)
                mutate(changed)
                with self.subTest(mutate=mutate), self.assertRaises(profile.ReplayError):
                    profile._verify_checkout_source(manifest, plan, files, changed,
                                                    root, allowed)
            (root / "converted.txt").write_bytes(b"one\r\nchanged\r\n")
            with self.assertRaisesRegex(profile.ReplayError,
                                        "original_checkout_bytes_changed"):
                profile._verify_checkout_source(manifest, plan, files, proof,
                                                root, allowed)
            (root / "converted.txt").write_bytes(converted)
            changed_files = {**files, "converted.txt": profile._digest(b"one\r\nchanged\r\n")}
            with self.assertRaisesRegex(profile.ReplayError,
                                        "checkout_projection_invalid"):
                profile._verify_checkout_source(manifest, plan, changed_files,
                                                proof, root, allowed)
            with self.assertRaisesRegex(profile.ReplayError,
                                        "checkout_projection_subject_mismatch"):
                profile._verify_checkout_source(manifest, plan, files, proof,
                                                root, frozenset({"scripts/cg_hook.py"}))

    def test_checkout_projection_descriptor_rejects_unlisted_fields(self):
        base = {key: None for key in profile.REPLAY_FIELDS}
        self.assertIsNone(profile._projection_descriptor(base))
        self.assertEqual(profile._source_delta_descriptor(
            {**base, "source_delta": {"path": "/proof", "sha256": "a" * 64}}),
            {"path": "/proof", "sha256": "a" * 64})
        self.assertEqual(profile._source_delta_descriptor(
            {**base, "source_delta": {"path": "/proof", "sha256": "a" * 64},
             "capture_snapshot": {"path": "/snapshot", "sha256": "b" * 64}}),
            {"path": "/proof", "sha256": "a" * 64})
        for changed in ({**base, "unexpected": {}},
                        {**base, "checkout_projection": {"path": "/tmp"}},
                        {**base, "source_delta": {"path": "/proof"}},
                        {**base, "source_delta": {"path": "/proof",
                                                   "sha256": "a" * 64},
                         "checkout_projection": {"path": "/projection",
                                                 "sha256": "b" * 64}}):
            with self.assertRaises(profile.ReplayError):
                profile._source_delta_descriptor(changed)

    def test_reviewed_four_file_delta_reconstructs_source_without_widening_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / "objects"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            paths = sorted(profile.SOURCE_DELTA_PATHS)
            names = paths + [f"fixtures/file-{index:03d}.txt" for index in range(208)]
            for name in names:
                target = repo / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("base " + name + "\n").encode())
            base_contents = {name: (repo / name).read_bytes() for name in names}
            subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false",
                            "add", "--", "."], check=True)

            def commit(message):
                subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false",
                                "-c", "user.name=Codex",
                                "-c", "user.email=12345+codex@users.noreply.github.com",
                                "commit", "-qm", message], check=True)
                return subprocess.check_output([
                    "git", "-C", str(repo), "rev-parse", "HEAD"
                ]).decode().strip()

            base = commit("base")
            (repo / "fixtures/file-000.txt").write_bytes(b"parent-only change\n")
            subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false",
                            "add", "--", "."], check=True)
            parent = commit("unrelated parent")
            for name in paths:
                (repo / name).write_bytes(("reviewed " + name + "\n").encode())
            subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false",
                            "add", "--", "."], check=True)
            reviewed = commit("four-file review")
            checkout = root / "harness"
            subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "-q",
                            "--no-hardlinks", str(repo), str(checkout)], check=True)
            subprocess.run(["git", "-C", str(checkout), "-c", "core.autocrlf=false",
                            "checkout", "-q", base], check=True)
            tracked = subprocess.check_output([
                "git", "-C", str(repo), "ls-tree", "-r", "--name-only", base
            ]).decode().splitlines()
            self.assertEqual(len(tracked), 212)
            for name in tracked:
                (checkout / name).write_bytes(base_contents[name])
            patch = subprocess.check_output([
                "git", "-C", str(repo), "diff", "--no-ext-diff", "--no-textconv",
                "--no-color", "--binary", base, reviewed, "--", *paths])
            patch_path = root / "four-files.patch"
            patch_path.write_bytes(patch)
            patch_sha = profile._digest(patch)
            subprocess.run(["git", "-C", str(checkout), "-c", "core.autocrlf=false",
                            "apply", str(patch_path)],
                           check=True, capture_output=True)
            files = {name: profile._digest(
                (repo / name).read_bytes() if name in paths else base_contents[name])
                for name in tracked}
            tree_sha = profile._digest(profile.fixture.canonical(files))
            runtime_sha = "d" * 64
            base_tree = profile._git_tree(repo, base)
            reviewed_tree = profile._git_tree(repo, reviewed)
            proof = {"schema": profile.SOURCE_DELTA_SCHEMA,
                     "base_commit": base, "reviewed_commit": reviewed,
                     "reviewed_parent": parent,
                     "patch": {"path": str(patch_path),
                               "sha256": patch_sha},
                     "source_manifest_sha256": "a" * 64,
                     "source_tree_sha256": tree_sha,
                     "runtime_tree_sha256": runtime_sha,
                     "paths": {name: {"base_blob": base_tree[name],
                                      "reviewed_blob": reviewed_tree[name]}
                               for name in paths}}
            manifest = {"original_source_commit": base,
                        "source_manifest": {"sha256": "a" * 64}}
            plan = {"harness_root": str(checkout),
                    "source_tree_sha256": tree_sha,
                    "runtime_tree_sha256": runtime_sha}
            with mock.patch.multiple(profile, SOURCE_DELTA_BASE=base,
                                     SOURCE_DELTA_REVIEWED=reviewed,
                                     SOURCE_DELTA_PARENT=parent,
                                     SOURCE_DELTA_PATCH_SHA256=patch_sha,
                                     SOURCE_DELTA_TREE_SHA256=tree_sha,
                                     SOURCE_DELTA_RUNTIME_SHA256=runtime_sha):
                self.assertEqual(profile._verify_source_delta(
                    manifest, plan, files, proof, repo)["reviewed_commit"], reviewed)
                with self.assertRaisesRegex(profile.ReplayError,
                                            "checkout_projection_invalid"):
                    profile._verify_checkout_source(manifest, plan, files, None, repo)
                for mutate in (
                    lambda p: p.update(reviewed_commit="0" * 40),
                    lambda p: p.update(base_commit="0" * 40),
                    lambda p: p.update(reviewed_parent="0" * 40),
                    lambda p: p["patch"].update(sha256="0" * 64),
                    lambda p: p["paths"][paths[0]].update(base_blob="0" * 40),
                    lambda p: p["paths"][paths[0]].update(reviewed_blob="0" * 40),
                    lambda p: p["paths"].update({"tools/validation/other.py": {}}),
                    lambda p: p.update(runtime_tree_sha256="0" * 64),
                    lambda p: p.update(source_manifest_sha256="0" * 64),
                ):
                    changed = deepcopy(proof)
                    mutate(changed)
                    with self.subTest(mutate=mutate), self.assertRaises(profile.ReplayError):
                        profile._verify_source_delta(manifest, plan, files, changed, repo)
                altered = {**files, paths[0]: "0" * 64}
                with self.assertRaisesRegex(profile.ReplayError,
                                            "source_delta_manifest_or_disk_changed"):
                    profile._verify_source_delta(manifest, plan, altered, proof, repo)
                extra = {**files, "tools/validation/unreviewed.py": "0" * 64}
                with self.assertRaisesRegex(profile.ReplayError,
                                            "source_delta_file_inventory_changed"):
                    profile._verify_source_delta(manifest, plan, extra, proof, repo)
                patch_path.write_bytes(patch + b"\n")
                with self.assertRaisesRegex(profile.ReplayError, "input_digest_changed"):
                    profile._verify_source_delta(manifest, plan, files, proof, repo)
                patch_path.write_bytes(patch)
                (checkout / paths[0]).write_bytes(b"changed after collection")
                with self.assertRaisesRegex(profile.ReplayError,
                                            "source_delta_manifest_or_disk_changed"):
                    profile._verify_source_delta(manifest, plan, files, proof, repo)

    def test_sealed_capture_snapshot_preserves_historical_closure_after_append(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, snapshot = root / "shared-capture", root / "snapshot"
            source.mkdir()
            snapshot.mkdir()
            files = {}
            events = (("SessionStart", "startup"), ("PreCompact", "auto"),
                      ("SessionStart", "compact"))
            for number, (event, trigger) in enumerate(events, 1):
                stem = f"capture-{number:06d}"
                value = {"session_id": "thread", "hook_event_name": event}
                value["trigger" if event == "PreCompact" else "source"] = trigger
                raw = json.dumps(value).encode()
                meta = json.dumps({"raw_sha256": profile._digest(raw),
                                   "raw_bytes": len(raw), "expected_event": event,
                                   "runtime_tree_sha256": "b" * 64}).encode()
                for directory in (source, snapshot):
                    (directory / (stem + ".raw")).write_bytes(raw)
                    (directory / (stem + ".meta.json")).write_bytes(meta)
                files[stem + ".raw"] = profile._digest(raw)
                files[stem + ".meta.json"] = profile._digest(meta)
            original_capture_sha = profile._tree_digest(snapshot)
            parent_path = root / "parent.json"
            parent_path.write_text(json.dumps({
                "original_capture_root": str(source),
                "files": {name: files[name] for name in sorted(files)[:2]}}))
            evidence = {"schema": "cg142-private-capture-snapshot/v1",
                        "original_capture_root": str(source),
                        "snapshot_root": str(snapshot),
                        "capture_tree_sha256": original_capture_sha,
                        "files": files,
                        "parent_snapshot_manifest_path": str(parent_path),
                        "parent_snapshot_manifest_sha256": profile._digest(
                            parent_path.read_bytes())}
            proof_path = root / "snapshot.json"
            proof_path.write_text(json.dumps(evidence))
            home = root / "home"
            session = (home / "plugins/data/context-guard-cg-candidate-unit"
                       / "sessions/thread")
            run, trace = root / "run", root / "trace"
            for directory in (session, run, trace):
                directory.mkdir(parents=True)
                (directory / "record").write_bytes(b"sealed")
            plan = {"capture_dir": str(source), "runtime_tree_sha256": "b" * 64,
                    "run_dir": str(run), "trace_root": str(trace),
                    "codex_home": str(home), "namespace": "cg-candidate-unit"}
            closure = {name: {"root": str(path), "sha256": profile._tree_digest(path)}
                       for name, path in (("run", run), ("trace", trace),
                                          ("session", session))}
            closure["capture"] = {"root": str(source),
                                  "sha256": original_capture_sha}
            manifest = {"closures": closure, "capture_snapshot": {
                "path": str(proof_path), "sha256": profile._digest(proof_path.read_bytes())}}
            (source / "capture-000004.raw").write_bytes(b"later scenario")
            (source / "capture-000004.meta.json").write_bytes(b"later meta")
            with self.assertRaisesRegex(profile.ReplayError,
                                        "evidence_closure_changed:capture"):
                profile._closures({"closures": closure}, plan)
            profile._closures(manifest, plan)
            self.assertEqual(profile._capture_snapshot(
                manifest, plan, "thread")["snapshot_root"], str(snapshot))
            wrong_closure = deepcopy(manifest)
            wrong_closure["closures"]["capture"]["sha256"] = "0" * 64
            with self.assertRaisesRegex(profile.ReplayError,
                                        "capture_snapshot_closure_mismatch"):
                profile._closures(wrong_closure, plan)
            with self.assertRaisesRegex(profile.ReplayError, "capture_snapshot_invalid"):
                profile._capture_snapshot(manifest, plan, "foreign")
            (snapshot / "extra").write_bytes(b"extra")
            with self.assertRaisesRegex(profile.ReplayError, "capture_snapshot_invalid"):
                profile._closures(manifest, plan)
            (snapshot / "extra").unlink()
            (source / "capture-000002.raw").write_bytes(b"changed original")
            with self.assertRaisesRegex(profile.ReplayError, "capture_snapshot_invalid"):
                profile._closures(manifest, plan)

    def test_failed_product_hook_blocks_replay_even_if_other_chain_observed(self):
        plan = {"hook_source": "/installed/hooks.json"}
        def row(source, status):
            return {"direction": "receive", "raw": {"method": "hook/completed",
                    "params": {"threadId": "thread", "run": {
                        "sourcePath": source, "source": "plugin", "status": status}}}}
        good = [row(plan["hook_source"], "completed"),
                row("/other/hooks.json", "failed")]
        profile._verify_product_hook_outcomes(good, plan, "thread")
        with self.assertRaisesRegex(profile.ReplayError, "product_hook_failed"):
            profile._verify_product_hook_outcomes(
                good + [row(plan["hook_source"], "failed")], plan, "thread")

    def test_official_hook_readback_requires_roles_events_and_trust(self):
        product_events = ("preToolUse", "postToolUse", "preCompact",
                          "sessionStart", "sessionEnd", "userPromptSubmit",
                          "subagentStart", "subagentStop", "stop")
        rows = []
        for index, event in enumerate(product_events):
            rows.append({"source": "plugin", "sourcePath": "/plugin/hooks.json",
                         "eventName": event, "key": f"product-{index}",
                         "currentHash": f"sha256:{index:064x}",
                         "trustStatus": "trusted", "enabled": True})
        for index, event in enumerate(("preCompact", "sessionStart")):
            rows.append({"source": "sessionFlags", "sourcePath": "/capture/config.toml",
                         "eventName": event, "command": "capture --digest-echo",
                         "key": f"capture-{index}",
                         "currentHash": f"sha256:{index + 9:064x}",
                         "trustStatus": "trusted", "enabled": True})
        plan = {"cwd": "/work", "hook_source": "/plugin/hooks.json",
                "capture_hook_source": "/capture/config.toml",
                "selected_hook_hashes": {h["key"]: h["currentHash"] for h in rows}}
        data = {"cwd": "/work", "errors": [], "warnings": [], "hooks": rows}
        profile._verify_hook_readback(data, plan)
        for index, field, value in ((0, "source", "sessionFlags"),
                                    (1, "eventName", "wrong"),
                                    (9, "command", "capture"),
                                    (10, "trustStatus", "untrusted")):
            changed = deepcopy(data)
            changed["hooks"][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(profile.ReplayError):
                profile._verify_hook_readback(changed, plan)

    def test_rpc_rejects_duplicate_or_reordered_host_records(self):
        good = [
            {"direction": "send", "raw": {"id": 1, "method": "initialize"},
             "monotonic_ns": 10},
            {"direction": "receive", "raw": {"id": 1, "result": {}},
             "monotonic_ns": 11},
        ]
        def encode(rows):
            return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        self.assertEqual(len(profile._rpc(encode(good))), 2)
        for changed in (good + [good[-1]], list(reversed(good)),
                        [dict(good[0], direction="forged"), good[1]]):
            with self.subTest(changed=changed), self.assertRaises(profile.ReplayError):
                profile._rpc(encode(changed))

    def test_rpc_uses_record_index_for_equal_clock_ticks_and_rejects_rollback(self):
        def encode(rows):
            return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        ordered = [
            {"direction": "send", "raw": {"id": 1}, "monotonic_ns": 100,
             "record_index": 1},
            {"direction": "send_complete", "raw": {"id": 1}, "monotonic_ns": 100,
             "record_index": 2},
            {"direction": "receive", "raw": {"id": 1}, "monotonic_ns": 101,
             "record_index": 3},
        ]
        self.assertEqual(profile._rpc(encode(ordered)), ordered)
        for changed in (
            [ordered[0], dict(ordered[1], record_index=1), ordered[2]],
            [ordered[0], dict(ordered[1], record_index=3), ordered[2]],
            [ordered[0], dict(ordered[1], monotonic_ns=99), ordered[2]],
            [ordered[0], {k: v for k, v in ordered[1].items()
                          if k != "record_index"}, ordered[2]],
            [ordered[0], dict(ordered[1], monotonic_ns=100.0), ordered[2]],
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    profile.ReplayError, "invalid_rpc_journal_order_or_shape"):
                profile._rpc(encode(changed))

    def test_bounded_file_read_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source.json"
            source.write_bytes(b"{}")
            digest = hashlib.sha256(b"{}").hexdigest()
            self.assertEqual(profile._read(source, digest, 2), b"{}")
            with self.assertRaises(profile.ReplayError):
                profile._read(source, "0" * 64, 2)
            with self.assertRaises(profile.ReplayError):
                profile._read(source, digest, 1)

    def test_bounded_file_read_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source.json"
            source.write_bytes(b"{}")
            digest = hashlib.sha256(b"{}").hexdigest()
            link = root / "link.json"
            self.symlink_or_skip(link, source)
            with self.assertRaises(profile.ReplayError):
                profile._read(link, digest, 2)

    def test_rpc_reply_must_follow_completed_send_even_when_ids_match(self):
        request = {"id": 7, "method": "initialize", "params": {}}
        reply = {"id": 7, "result": {}}
        def row(direction, raw, stamp):
            return {"direction": direction, "raw": raw,
                    "monotonic_ns": stamp}
        good = [row("send", request, 10), row("send_complete", request, 11),
                row("receive", reply, 12)]
        self.assertEqual(profile._response(good, "initialize"), (request, reply))
        for changed in (
            [row("receive", reply, 10), row("send", request, 11),
             row("send_complete", request, 12)],
            [row("send", request, 10), row("receive", reply, 11),
             row("send_complete", request, 12)],
        ):
            with self.subTest(changed=changed), self.assertRaises(profile.ReplayError):
                profile._response(changed, "initialize")

    def test_partial_postbusiness_source_requires_matching_terminal_and_product_hook(self):
        source = "/plugin/hooks.json"
        thread, turn, call = "thread-1", "turn-1", "exec-1"
        terminal = {"method": "item/completed", "params": {
            "threadId": thread, "turnId": turn, "item": {
                "type": "dynamicToolCall", "id": call,
                "status": "completed", "success": True}}}
        hook_id = f"post-tool-use:10:{source}:{call}"
        hook = {"method": "hook/completed", "params": {
            "threadId": thread, "turnId": turn, "run": {
                "id": hook_id, "sourcePath": source, "eventName": "postToolUse",
                "status": "completed", "statusMessage": None,
                "source": "plugin", "handlerType": "command",
                "executionMode": "sync", "scope": "turn"}}}
        def row(raw):
            return {"direction": "receive", "raw": raw}
        rows = [{"direction": "send_complete", "raw": {"id": "reply"}},
                row(terminal), row(hook)]
        args = ({"hook_source": source}, thread, turn, call, 0)
        self.assertEqual(profile._postbusiness_source(rows, *args),
                         (call, hook_id, 2))
        variants = []
        for target, field, value in ((1, "success", False),
                                     (2, "sourcePath", "/other/hooks.json"),
                                     (2, "status", "failed"),
                                     (2, "id", hook_id + "-other")):
            changed = deepcopy(rows)
            branch = changed[target]["raw"]["params"]
            (branch["item"] if target == 1 else branch["run"])[field] = value
            variants.append(changed)
        variants.append([rows[0], rows[2], rows[1]])
        variants.append([rows[0], rows[1], row({"method": "item/completed",
            "params": {"item": {"type": "commandExecution"}}}), rows[2]])
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(profile.ReplayError):
                profile._postbusiness_source(changed, *args)

    def test_evidence_tree_digest_detects_changed_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "capture.raw"
            first.write_bytes(b"original")
            original = profile._tree_digest(root)
            first.write_bytes(b"changed")
            self.assertNotEqual(profile._tree_digest(root), original)

    def test_evidence_tree_digest_rejects_linked_member(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            first = root / "capture.raw"
            first.write_bytes(b"original")
            linked = root / "linked.raw"
            self.symlink_or_skip(linked, first)
            with self.assertRaisesRegex(profile.ReplayError, "linked_tree_member"):
                profile._tree_digest(root)

    def test_manifest_cannot_claim_success_without_exact_raw_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"schema": profile.SCHEMA,
                                            "status": "passed"}))
            with self.assertRaisesRegex(profile.ReplayError, "invalid_replay_manifest"):
                profile.replay(manifest)
            manifest.write_text('{"schema":"x","schema":"y"}')
            with self.assertRaisesRegex(profile.ReplayError, "duplicate_json_key"):
                profile.replay(manifest)

    def test_versioned_result_schema_declares_profile_and_required_gate_facts(self):
        schema = json.loads((Path(__file__).parents[1] / "tools/validation"
                             / "native-acceptance-v2.schema.json").read_text())
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertIn(profile.PROFILE, schema["properties"]["gate_profile"]["enum"])
        required = schema["properties"]["gates"]["items"]["required"]
        self.assertIn("evidence", required)
        self.assertIn("mode", schema["properties"]["gates"]["items"]
                      ["properties"]["evidence"]["required"])


if __name__ == "__main__":
    unittest.main()
