# Independent answer review — 0.14.2 source candidate

This is an explicit, bounded interface under development, not accepted native
behavior. It does not automatically call a model from a Hook.

The operator must first configure a private `answer-reviews/policy.json` for
the session, with `version`, `active`, `binary` and `binary_sha256`. The binary
must be the operator-verified Codex executable. A review request cannot create
this policy or select a new authority. This trust configuration is separate
from the model's output: a model cannot nominate its own executable or assert
`trusted: true`. The local policy and capture key are not protected against
arbitrary writes by the same OS account; Context Guard is not a sandbox.

The `review-answer` command takes the existing session/turn private token,
question identity and matching binary/version pins. Without `--execute`, it
cannot invoke the reviewer. With it, the collector reconstructs the complete
root and exact question span, reads actual messages and verifies the source
again before sending. It invokes one fresh ephemeral Codex exec process in a
temporary working directory with the read-only sandbox, using the existing
model configuration and authentication. It does not resume the answer producer,
install anything, bypass trust, retry or loop. Input and captured output are
limited to 2 MiB and the process has a 60-second deadline. Observed tool use
invalidates the judgment; read-only execution is not a universal guarantee of
no external effects. POSIX uses a new process group and checks its disappearance;
on macOS, a group that remains must have no running members by a complete
system readback. Group absence and no-running membership are distinct results;
denied or unknown readback fails closed. Windows starts the process suspended, assigns it to a
kill-on-close Job Object, then resumes it; a zero-model native probe observed
an owned child exit after the leader had already exited. Escaped descendants
remain outside the verified route. Independent review on the repaired installed
runtime and the complete model chain still require native validation.

The output is constrained by a strict decoder to `verdict`, `information_only`,
target-relevant `message_ids`, and explicit per-message `associations` against
the exact question catalog. These associations are independent-review judgments,
not invented Host fields. Only a separate successful reviewer run can
create a collector-sealed receipt. The receipt contains the actual private
request/output, exact source references, authority version and adapter digest.
Cold replay rechecks it; changing the collector invalidates old receipts.

`--supersedes` names exact prior judgment IDs for a correction. Missing parents,
cycles, forks, mismatched subjects or ambiguous message order remain unknown.
`--revoke` retires the current authority identity without a model call; old
receipts cannot be reactivated under that identity. A different policy version
needs a new explicit operator configuration.

A complete information judgment changes only the current answer projection.
It is a fallible semantic review, never a Host fact, execution proof, tool
permission or release approval. Pending execution, prohibitions and waits stay
unchanged. A later unreviewed answer or correction for the same question
invalidates current coverage. No sidecar means no change to old state; no
migration infers delivery from summaries. Missing/ambiguous question association
remains unknown. Same-root associations now come from explicit independent-review output; source
tests cover per-question preservation and conflicts. Native semantic accuracy
remains an acceptance gap.

## Normal-flow owner

With an adopted and configured policy, the task agent invokes `review-pending`
once after delivering a side-answer commentary and before continuing business
work. The packaged Skill specifies this trigger. The command claims an exact
input before starting at most one call. Unrelated transcript growth does not
create new work; unchanged failed/partial inputs are not retried automatically.
New deliveries or authority versions can create new inputs. A new assessment
can supersede only its unique source-validated predecessor for that question.
This is agent-mediated scheduling, not a native Host guarantee. Other queued
questions can remain pending after the single-call budget, and no ordinary
permission or main-task completion follows from queue status.

## Transcript selection and budgets

Transcript JSON is decoded separately from strict review receipts: ordinary
finite numeric metadata, including exponent notation, is legal. Duplicate keys,
non-finite values, invalid Unicode, over-depth records and oversized lines remain
unavailable. Relevant message identity/time fields retain their strict types.

The display's last-512-message window is not the review input. Review scans the
whole stable transcript for identity conflicts, then selects candidate messages
for the source-bound eligible roots. Each root has its own 512-message and
2 MiB retained-text budget; an overflowing root remains unknown without blocking
a different root. No semantic keyword filtering chooses the messages. The whole
file still has the existing 512 MiB and 8192-message-identity integrity limits,
and each line is bounded at 2 MiB. The final reviewer request also retains its
2 MiB input limit. Selection does not hide a conflict in unselected history.
