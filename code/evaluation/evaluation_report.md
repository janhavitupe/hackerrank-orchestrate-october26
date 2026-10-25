# Evaluation report

Scorer: `code/evaluation/evaluate.py`. Steps are compared as whole tuples
`(phase, system_id, resource_id, operation, state, evidence_id)`.

| Metric | Definition |
|---|---|
| Status accuracy | `deletion_status` exact match per case |
| Sequence accuracy | the whole `steps_json` array identical, order included, step numbers 1..n |
| Step P/R/F1 | multiset match of step tuples (also reported without `evidence_id`) |
| Field accuracy | steps aligned by position, share of the 6 fields that match (missing or extra steps count as misses) |
| Resource P/R/F1 | discovered `(system_id, resource_id)` pairs per case |

## 1. Public samples (32 cases, `dataset/sample_output.csv`)

Final run: `python code/main.py --samples`. The samples are audited together with the 518
evaluation requests, because they share one activity stream.

| Metric | Final |
|---|---:|
| Status accuracy | **1.000** (32/32) |
| Sequence accuracy | **0.938** (30/32) |
| Step precision / recall / F1 | **1.000 / 0.990 / 0.995** |
| Step P/R/F1 ignoring evidence_id | 1.000 / 0.990 / 0.995 |
| Field accuracy (positional) | **0.976** |
| Resource precision / recall / F1 | 1.000 / 0.982 / 0.991 |

The two remaining sequence mismatches (case_04 and case_23 were fixed in session 2, see §4 rows 14–16):

| Case | Difference | Why |
|---|---|---|
| case_18 | missing `audit_record_6645` PRESENT | Not present in any evidence file or activity. Unreachable. |
| case_20 | missing `audit_record_5569` PRESENT | Same: not present anywhere. |

## 2. Custom evaluation cases (created by us)

`code/evaluation/custom_cases/requests.csv` holds the cases, `expected.csv` the answers. Each
case targets one capability. The expected outputs are either the published sample answer under a
controlled change that must not alter it (C1, C3), or were derived by hand from the raw evidence
(C2, C4, C5, C6).

| # | Capability | Construction | Expected | Result |
|---|---|---|---|---|
| custom_01 | Historical identifier | sample case_12 filed with the subject's **old** email `minjun.kim90@gmail.com` | identical to gold case_12 (old-hash secondary record deleted) | pass |
| custom_02 | Non-deletion in Spanish with deletion vocabulary | "...envíenme una copia de mis datos... No eliminen mi cuenta" | `NOT_APPLICABLE`, `[]` | pass (failed before the multilingual negation fix) |
| custom_03 | Language + email normalisation | sample case_14 in Korean, email upper-cased | identical to gold case_14 | pass |
| custom_04 | Look-alike decoy in a screenshot | `g.silva76@gmail.com`; the search screen also shows `search_1874` for `g.silva76.jr@gmail.com` | only `search_428` (remaining, evidence_09), never `search_1874`; plus the convention account `account_013` verified absent (expectation updated in session 2) | pass |
| custom_05 | Request-window scoping | sample case_07 filed in February, so the February support attachment `object_19` (screenshot + catalog link) is in scope | gold case_07 plus `object_19` finding/delete/verify | pass |
| custom_06 | French marketing-only opt-out | "retirer des listes marketing uniquement. Ne supprimez pas mon compte" | `NOT_APPLICABLE`, `[]` | pass |
| custom_07 | Audit cut-off (diagnostic) | sample case_26 with `audit_at` moved to 10 Sep, before the 15 Sep read-back that proves deletion | `INCOMPLETE`: the 9 Sep snapshot still shows `account_5684` ACTIVE | produces INCOMPLETE; see limitation L3 |

Scores on C1–C6: status 1.000, sequence 1.000, step F1 1.000, field 1.000.

## 3. Full evaluation set (518 cases, no labels): consistency checks

| Check | Result |
|---|---|
| Rows / header / ordering / JSON validity / allowed phase-operation-state | 518 rows, all valid (contract validator in the dev log) |
| Status mix | 355 INCOMPLETE, 153 COMPLETE, 10 NOT_APPLICABLE |
| NOT_APPLICABLE | exactly the 10 texts that the activity log's `CLASSIFY_REQUEST` rows also flag as non-deletion |
| COMPLETE steps citing evidence captured after `audit_at` | 0 (was 12 before the citation fix) |
| COMPLETE steps citing only an activity id | 0 |
| A resource linked to more than one request | 0 |
| Requests with no account resolved | 1 (case_53: the convention id `account_022` belongs to another customer, so it is not used) |
| Account picks decided by tie-break | 26 requests (13 pairs), down from 85 |

## 4. Failures found and improvements made (chronological)

| # | Failure observed | Fix | Effect on samples |
|---|---|---|---|
| 1 | First end-to-end run | baseline | status 0.812, seq 0.375, step F1 0.834 |
| 2 | Follow-up deletion texts ("finish the deletion", "remove that search result") classified as non-deletion | explicit negations take priority; any deletion vocabulary otherwise means deletion | status 0.812 → 0.938 |
| 3 | A `user_17` alias text-matched inside the legal register PDF, linking a tombstone to six users | PDF aliases restricted to business aliases (never bare ids) | removed 5 false steps |
| 4 | Old evidence leaking into later requests (Feb attachment in a Sep request) | resources must be observed inside `[requested_at, audit_at]` | removed false findings |
| 5 | Records whose only evidence sits in a later export were missed (snapshot captured before the audit, exported after it) | visibility uses the observation's own timestamp; citations use only files captured by `audit_at` | +4 audit records |
| 6 | Per-request activity linking let one request take another's anonymised analytics (±2 s tolerance) | joint per-burst solving, nearest anchor wins, tolerance 1.5 s | status → 1.000, seq 0.875 |
| 7 | Adjacent hourly bursts overlapped (100-minute window) and stole accounts | account window narrowed to 39–80 minutes, measured from evidence-resolved pairs | fixed case_277 class |
| 8 | Snapshot lookup rows using `lookup_value` instead of `subject_reference` were dropped | both keys read | +22 eval cases gained audit records |
| 9 | Legacy support-replica contact records treated as conversations (redact) | contact-index records categorised as secondary identifiers (delete) | case_10 fixed |
| 10 | A stale snapshot said "present" while a newer full inventory omitted the account | omission from a full profile capture counts as absence, unless the last copy was a replica (drift) | 1 eval case flipped to COMPLETE; sample case_05 kept |
| 11 | 12 citations pointed at files captured after `audit_at` | account absence cited from the case's dominant capture, then the latest full capture | 0 non-citable citations |
| 12 | Catalog link rejected because the screen showed an unknown persona, leaving an empty COMPLETE | reject only if identifiers resolve to a *different known* customer | case_63 non-empty |
| 13 | English-only negations (found while building custom_02) | ES/FR/PT/KO/JA negation and non-deletion patterns | custom_02 / custom_06 pass |
| 14 | Account ties inside a burst (case_23 got `account_7015`, gold `account_410`) | measured a second signature: the worker's post-report "final result" and check events land at account-delete second + 21.5 (mod 30), in two waves (+52 s / +22 s), across 250+ evidence-resolved events. Used as a second filter after the pre-report policy anchor | case_23 fixed; eval tie-breaks 85 → 26; 41 eval rows changed (mostly swapped account pairs) |
| 15 | Requests with no account deletion in their burst got no account at all (case_04, 10 eval cases) | fall back to the profile-table naming convention `user_N -> account_{N:03d}` (seen in every SQL profile table and in sample cases 01–10), only if no other customer owns that id | case_04 resource found; 9 of 10 eval cases gained an account |
| 16 | The convention account was cited from an inventory with no profile rows (evidence_90) | a never-observed account's absence is cited only from a capture that contains profile rows | case_04 now cites evidence_54 as gold does |

**Investigated and rejected:** we tested whether account order inside a burst follows request
age, case number or user number, using 208 evidence-resolved pairs. Agreement was 66–72 of 208,
which is chance level for bursts of 2–3. That signal was dropped.

## 5. Known limitations

- **L1 Burst ties.** When two requests in the same burst have the same claimed status and nothing
  identifiable (deleted account plus fully anonymised analytics), the pairing is not
  determinable from participant data. We pick a pairing consistent with the second-offset
  signature. 26 such ties (13 pairs) remain in the evaluation set: in each pair both candidate accounts share the same second modulo 30, so neither timing signature separates them, so some account/analytics pairs will
  be swapped.
- **L2 Unobservable gold resources.** Some retained audit records (case_18, case_20) appear in no evidence, so they can't be produced without guessing.
- **L3 Cut-off citation fallback.** If the only evidence for a state is a file exported after
  `audit_at` (custom_07), the finding still cites it, so the problem stays visible instead of
  being dropped. This never happens in the 518-case output.
