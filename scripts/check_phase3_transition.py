#!/usr/bin/env python3
"""Audit the frozen Phase-1 baseline against the Phase 3/4 transition manifest.

The historical baseline ``tests/test_context_guard_012_baseline.py`` is
byte-frozen (sha256 9deeef27be0c0476816c4bc74741816617f8ea613c83002860a8058cd4630be8).
After the Phase 3 (schema 10 + Stop 3.0) and Phase 4 (profiles +
position-aware PreToolUse) implementations it MUST report exactly the
transition state this manifest describes and nothing else:

* every 0.12 target scoped to Phase 3, plus the Phase-4 targets UX-06
  (executable position) and UX-07 (simulation semantics), is an unexpected
  success (``EXPECTED_FIXED_TARGETS``);
* UX-05 is closed by the Phase-4 conformance suite
  (``tests.test_context_guard_phase4.ProfileLadderTests`` and
  ``AllowSilenceAndDenyReasonTests``) under the frozen plan section 4.4
  wire, where an authorized real mutation returns the PLAIN EMPTY OBJECT.
  The frozen pin
  ``PolicyScopeBaselineTests.test_root_user_authorized_tag_still_requires_ticket``
  additionally asserted the OLD explicit-allow wire shape
  (``hookSpecificOutput.permissionDecision == "allow"``). That wire
  assertion is SUPERSEDED/OVER-SPECIFIED by section 4.4 and cannot be
  satisfied without violating the plan, so it is expected to raise
  (``SUPERSEDED_WIRE_ASSERTIONS``) — recorded honestly, never faked;
* no Phase-4-scope target remains an expected failure
  (``EXPECTED_REMAINING_TARGETS`` stays empty as a tripwire);
* every 0.11.x defect pin documents an inverted observation
  (``EXPECTED_INVERTED_PINS``) — the failure IS the deliverable;
* zero unexpected errors of any other kind.

All counts are formed from the REAL harness output and matched against the
manifest sets; nothing is presupposed. Exit 0 iff the observed outcome set
equals the manifest exactly.

NOTE (Phase 5): the manifest/report naming keeps the historical
``check_phase3_transition`` identity so gate evidence stays comparable;
it now audits the combined Phase 3+4 transition.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = ROOT / "tests" / "test_context_guard_012_baseline.py"
BASELINE_SHA256 = "9deeef27be0c0476816c4bc74741816617f8ea613c83002860a8058cd4630be8"

# 0.12 targets fixed by the Phase 3+4 candidates (unexpected success):
# the 22 Phase-3 targets plus the Phase-4 UX-06/UX-07 inversions.
EXPECTED_FIXED_TARGETS = [
    "AdapterBindingBaselineTests.test_qualified_name_binds_readback_subject",
    "AdapterBindingBaselineTests.test_read_adapter_binds_thread_id_from_structured_input",
    "EvidenceUniquenessBaselineTests.test_non_unique_evidence_is_not_auto_selected",
    "ExecutablePositionBaselineTests.test_plan_false_positive_table_is_classified_as_action",
    "OwnerLadderFixtureTests.test_target_assistant_declared_user_wait_mismatch",
    "OwnerLadderFixtureTests.test_target_assistant_partial_no_persistence",
    "OwnerLadderFixtureTests.test_target_assistant_persistence_budget",
    "OwnerLadderFixtureTests.test_target_deferred_by_scope",
    "OwnerLadderFixtureTests.test_target_external_declared_deferred_subclass",
    "OwnerLadderFixtureTests.test_target_external_registered_operation",
    "OwnerLadderFixtureTests.test_target_goal_prompt_assistant",
    "OwnerLadderFixtureTests.test_target_unknown_ambiguous",
    "OwnerLadderFixtureTests.test_target_user_missing_input",
    "OwnerLadderFixtureTests.test_target_whole_claim_no_persistence_no_obligations",
    "OwnerLadderFixtureTests.test_target_whole_claim_persistence",
    "ReasonCodeFixtureTests.test_production_structured_matcher_api",
    "SchemaMigrationBaselineTests.test_schema_version_is_10_with_migration",
    "SchemaMigrationTargetTests.test_schema10_migration_isolates_chain_without_marking_pass",
    "SchemaMigrationTargetTests.test_schema10_resume_policy_unique_and_tie",
    "SimulationBaselineTests.test_dry_run_variants_are_treated_as_real_mutations",
    "StopCascadeBaselineTests.test_correction_budget_is_one_visible_block",
    "StopCascadeBaselineTests.test_disposition_comparator_treats_waits_equivalently",
    "WaitingOwnerStructuredTests.test_assistant_owner_terminal_persistent_completion_gates",
    "WorkUnitLifecycleBaselineTests.test_new_independent_request_starts_a_sibling_root",
]

# Phase-4-scope 0.12 targets: intentionally still expected failures.
# Empty tripwire — any entry must correspond to a real planned deferral.
EXPECTED_REMAINING_TARGETS: list[str] = []

# UX-05 legacy wire assertion, superseded by frozen plan section 4.4.
# The pin's AUTHORIZATION semantics (explicit root-user statement in the
# current work unit allows the tag) is real 0.12 behavior and IS verified —
# by tests.test_context_guard_phase4 under the correct empty-object wire.
# The pin additionally demanded the old explicit-allow wire shape, which
# section 4.4 forbids, so with the real behavior in place it raises
# (KeyError on the absent hookSpecificOutput). Recorded here as the
# documented deliverable of the wire correction; never special-cased in
# production code and never faked as a pass.
SUPERSEDED_WIRE_ASSERTIONS = [
    (
        "PolicyScopeBaselineTests.test_root_user_authorized_tag_still_requires_ticket",
        "UX-05",
        "superseded/over-specified legacy wire assertion: section 4.4 "
        "requires the allow path to return the plain empty object without "
        "permissionDecisionReason; UX-05 itself is closed by the Phase-4 "
        "conformance suite",
    ),
]

# 0.11.x defect pins whose frozen observation Phase 3 legitimately inverts.
EXPECTED_INVERTED_PINS = [
    (
        "AdapterBindingBaselineTests.test_qualified_thread_read_binds_no_subject",
        "UX-09",
    ),
    (
        "AdapterBindingBaselineTests.test_thread_readback_obligation_cannot_close",
        "UX-09",
    ),
    (
        "OwnerLadderFixtureTests.test_owner_rows_isolated_sessions_lexical_observation"
        " (row='assistant_declared_user_wait_mismatch')",
        "UX-02/UX-03",
    ),
    (
        "OwnerLadderFixtureTests.test_owner_rows_isolated_sessions_lexical_observation"
        " (row='assistant_persistence_budget')",
        "UX-02",
    ),
    (
        "OwnerLadderFixtureTests.test_owner_rows_isolated_sessions_lexical_observation"
        " (row='external_declared_deferred_subclass')",
        "UX-03",
    ),
    (
        "OwnerLadderFixtureTests.test_owner_rows_isolated_sessions_lexical_observation"
        " (row='whole_claim_persistence')",
        "UX-02",
    ),
    (
        "ReasonCodeFixtureTests.test_legacy_observations_match_frozen_results"
        " (row='selection_order_dependent_legacy', observation_class='legacy_observation')",
        "INV-evidence-uniqueness",
    ),
    (
        "ReplayLaneTests.test_replay_lane_t1_work_unit_debt_and_unbounded_feedback",
        "UX-01/UX-08",
    ),
    (
        "ReplayLaneTests.test_replay_lane_t2_checkpoint_failure_cascade",
        "UX-02",
    ),
    (
        "ReplayLaneTests.test_replay_lane_t3_disposition_subclass_chain",
        "UX-03",
    ),
    (
        "StopCascadeBaselineTests.test_correction_chain_closes_with_matching_disposition",
        "UX-02/UX-03",
    ),
    (
        "StopCascadeBaselineTests.test_repeated_mismatch_exhausts_budget_with_hard_stop",
        "UX-02",
    ),
    (
        "StopCascadeBaselineTests.test_subclass_disposition_differences_cause_visible_blocks",
        "UX-03/UX-08",
    ),
    (
        "WorkUnitLifecycleBaselineTests.test_each_prompt_chains_a_child_unit",
        "UX-01",
    ),
    (
        "WorkUnitLifecycleBaselineTests.test_replay_over_120_turns_keeps_units_active",
        "UX-01",
    ),
]


def short_id(test) -> str:
    """tests.module.Class.method (subTest suffix dropped of the module)."""
    parts = test.id().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else test.id()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None, help="write the report JSON here")
    args = parser.parse_args()

    digest = hashlib.sha256(BASELINE_FILE.read_bytes()).hexdigest()
    if digest != BASELINE_SHA256:
        print(f"FAIL frozen baseline bytes changed: {digest}")
        return 1

    sys.path.insert(0, str(ROOT))
    import tests.test_context_guard_012_baseline as baseline  # noqa: E402

    suite = unittest.TestLoader().loadTestsFromModule(baseline)
    result = unittest.TextTestRunner(verbosity=0, stream=sys.stderr).run(suite)

    observed_fixed = sorted(short_id(test) for test in result.unexpectedSuccesses)
    observed_remaining = sorted(short_id(test) for test, _ in result.expectedFailures)
    # test.id() already carries the ``(key=value)`` subTest suffix.
    observed_inverted = sorted(short_id(test) for test, _ in result.failures)
    all_errors = sorted(short_id(test) for test, _ in result.errors)
    expected_failures = sorted(short_id(test) for test, _ in result.expectedFailures)
    # expectedFailure swallows ANY exception, so the superseded wire
    # assertion (KeyError on the absent explicit-allow shape) surfaces as
    # an expected failure, not an error. Classify over both buckets.
    superseded_ids = {item for item, _family, _note in SUPERSEDED_WIRE_ASSERTIONS}
    observed_superseded = sorted(
        item for item in (all_errors + expected_failures) if item in superseded_ids
    )
    observed_errors = [item for item in all_errors if item not in superseded_ids]
    observed_remaining = [
        item for item in observed_remaining if item not in superseded_ids
    ]

    deltas: list[str] = []
    superseded_families = {
        item: family for item, family, _note in SUPERSEDED_WIRE_ASSERTIONS
    }
    for label, observed, expected in (
        ("fixed target not passing (regression)", observed_fixed, EXPECTED_FIXED_TARGETS),
        (
            "phase-4 target left the expected-failure set",
            observed_remaining,
            EXPECTED_REMAINING_TARGETS,
        ),
        ("unexpected inverted pin", observed_inverted, [item for item, _ in EXPECTED_INVERTED_PINS]),
    ):
        for item in sorted(set(observed) - set(expected)):
            deltas.append(f"{label}: {item}")
        for item in sorted(set(expected) - set(observed)):
            deltas.append(f"missing from {label} set: {item}")
    for test_id in observed_errors:
        deltas.append(f"unexpected error: {test_id}")
    for label, observed, expected in (
        (
            "superseded wire assertion not observed as an error",
            observed_superseded,
            sorted(superseded_ids),
        ),
    ):
        for item in sorted(set(observed) - set(expected)):
            deltas.append(f"{label} (it now passes or behaves differently): {item}")
        for item in sorted(set(expected) - set(observed)):
            deltas.append(f"missing from {label} set: {item}")

    report = {
        "baseline_sha256": digest,
        "tests": result.testsRun,
        "fixed_targets": observed_fixed,
        "remaining_expected_failures": observed_remaining,
        "superseded_wire_assertions": [
            {
                "test": item,
                "family": superseded_families[item],
                "note": note,
            }
            for item, _family, note in SUPERSEDED_WIRE_ASSERTIONS
            if item in observed_superseded
        ],
        "inverted_defect_pins": observed_inverted,
        "errors": observed_errors,
        "inverted_pin_families": sorted(
            {family for test_id, family in EXPECTED_INVERTED_PINS if test_id in observed_inverted}
        ),
        "matches_manifest": not deltas,
        "deltas": deltas,
    }
    if args.json:
        args.json.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "baseline_sha256": digest[:12] + "...",
                "tests": result.testsRun,
                "fixed_targets": len(observed_fixed),
                "remaining_expected_failures": len(observed_remaining),
                "superseded_wire_assertions": len(observed_superseded),
                "inverted_defect_pins": len(observed_inverted),
                "errors": len(observed_errors),
                "matches_manifest": not deltas,
            },
            ensure_ascii=False,
        )
    )
    for delta in deltas:
        print("!", delta)
    return 0 if not deltas else 1


def _subtest_suffix(repr_text: str) -> str:
    """Extract the ``(key=value)`` subTest suffix from ``str(test)``.

    ``str(test)`` looks like ``method (dotted.id)`` or
    ``method (dotted.id) (key=value)``; only a trailing group carrying an
    ``=`` is a subTest suffix.
    """
    marker = ") ("
    index = repr_text.find(marker)
    if index >= 0 and "=" in repr_text[index + len(marker):]:
        return " (" + repr_text[index + len(marker):]
    return ""


if __name__ == "__main__":
    raise SystemExit(main())
