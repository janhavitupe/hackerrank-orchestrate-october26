# Ghost Data Still Exists - deletion audit agent

For every request in `dataset/deletion_requests.csv`, the agent decides whether deletion was
actually requested. It then rebuilds the subject's footprint across all evidence as it stood at
`audit_at`, applies `deletion_rules.csv`, and writes `COMPLETE` / `INCOMPLETE` / `NOT_APPLICABLE`
together with ordered findings, remediation and verification steps.

## Setup and run

Requirements: Python 3.10+ (standard library only). `pdftotext` (poppler) is used for PDFs when
it's on `PATH`; otherwise `pypdf` is used. The optional LLM pass needs `pip install anthropic`
and Anthropic credentials (`ANTHROPIC_API_KEY`).

```bash
# from the repository root
python code/main.py                 # 518 requests -> ./output.csv (+ code/evaluation/usage_report.md)
python code/main.py --no-llm        # rule-only intent classification
python code/main.py --samples       # public samples -> code/evaluation/sample_predictions.csv
python code/evaluation/evaluate.py dataset/sample_output.csv code/evaluation/sample_predictions.csv --show
# custom evaluation cases
python code/main.py --requests code/evaluation/custom_cases/requests.csv --out code/evaluation/custom_cases/predictions.csv
python code/evaluation/evaluate.py code/evaluation/custom_cases/expected.csv code/evaluation/custom_cases/predictions.csv --subset --show
```

A full run takes about 5 seconds and is deterministic: same inputs, byte-identical `output.csv`.
Secrets are read only from the environment, and nothing is written to the repository except outputs.

## Layout

| File | Role |
|---|---|
| `main.py` | Orchestrates the three phases and writes `output.csv` and the usage report |
| `ingest.py` | Parses every evidence format into uniform *observations* (time, file, resource, state, identifiers) |
| `audit.py` | Identity resolution, linking, state at `audit_at`, policy, step generation |
| `intent.py` + `prompts/intent_classifier.md` | Multilingual rule classifier, plus a batched, cached LLM pass for uncertain texts |
| `image_extractions.json` | Cached multimodal transcription of the 11 screenshots |
| `evaluation/` | Scorer, custom cases, `evaluation_report.md`, `usage_report.md` |

## How it works

**1. Ingestion (`ingest.py`).** Every file listed in `evidence_files.csv` becomes a list of
observations:

- **JSON:** snapshot bundles (each snapshot has its own `captured_at`), service read-back
  exports, record manifests and collections.
- **SQL:** executed in in-memory SQLite. This covers typed inventories with `snapshot_scope`,
  JSON-in-SQL primary/replica tables (read, regional, reporting, failover), and typed profile
  dumps.
- **Logs:** one tolerant line parser handles key=value, JSON-lines, syslog, bracketed,
  pipe-delimited and cloud-runtime dialects. Lines are grouped by `trace_id`, so the lookup key
  on a `*_started` line is attached to the result on the `*_completed` / scan line.
- **Text and PDFs:** handover text rows and the shared `record_lookup` shape. PDFs go through
  `pdftotext`; their resource ids and printed identifiers are extracted, including catalogued
  business aliases such as statement numbers.
- **Screenshots:** read from the multimodal cache.

**2. Identity.** Each request email (case-insensitive) resolves to one `user_id`. The identifier
set is the current snapshot plus every value in `user_audit_log.csv`: old emails, phones and
hashes, plus SHA-256 of every email (that is how `email_hash` is defined).

**3. Linking (three phases, all requests together).**

1. *Evidence:* a resource belongs to the subject when an observation carries one of their
   identifiers and the resource was observed inside the request window
   `[requested_at, audit_at]`. Look-up hits whose stored identifiers belong to someone else are
   rejected, which handles look-alike decoys such as `g.silva76.jr@`.
2. *Catalog:* `LINK_RESOURCE_IDENTITY` claims are accepted unless the record's own identifiers
   resolve to a different known customer.
3. *Activity fallback:* deleted accounts and fully anonymised analytics carry no identifiers.
   The deletion worker handles all requests reported at the same instant in one burst. Account
   deletions run 39-80 minutes before `reported_at`, and their result mirrors the workflow claim
   (COMPLETE→SUCCESS, PARTIALLY_COMPLETE→PARTIAL, NOT_STARTED→FAILED). Policy actions run 7-29
   minutes before, at a fixed second offset from the same request's account deletion (anchor =
   account second + 41 s; redact +29.5 s, disable −1.5 s, block +28.5 s from the anchor). The
   worker's post-report results and checks for the request's evidence-linked records land at the
   account second + 21.5 s (mod 30), which gives a second filter for the account. Each burst is
   solved as a whole: unique matches first, then elimination, then nearest anchor. That way one
   record is never assigned to two people.
4. *Naming convention:* a request still without an account gets `account_{N:03d}` for `user_N`
   (the convention seen in the profile tables), unless another customer owns that id. Its absence
   is cited from the latest profile-table capture that omits it.

**4. State at `audit_at`.** The latest observation with timestamp ≤ `audit_at` decides presence,
exposed PII, enabled flows and restorable backups. All copies seen at that instant are combined:
if any replica still holds the record, it is present (replication drift). Omission from a later
*full* profile-table capture counts as absence, except when the copy we last saw was in a replica.
Citations only use files captured on or before `audit_at`, preferring explicit observations.

**5. Policy and steps.** Categories come from the evidence (`record_type`, collection names, log
event types) or from the resource kind, and `deletion_rules.csv` maps each to a required state:
ABSENT / REDACTED / ANONYMIZED / PRESENT (retain), with DISABLED for data flows and BLOCKED for
backups. A mismatch becomes a finding plus its remediation. Every linked resource gets a
verification of its required final state. Within each phase, steps are ordered by the operation
order in the table, then `system_id`, then `resource_id`. INCOMPLETE remediation and
verification steps carry `evidence_id=""`; COMPLETE verifications cite the proving file.

**6. Intent.** `NOT_APPLICABLE` with `[]` is used when the text doesn't authorise deletion. The
rule classifier covers English, Spanish, French, Portuguese, Korean and Japanese phrasing and
gives explicit negations priority ("do not close", "marketing lists only", "copy of the
information"). Low-confidence texts go to `claude-opus-5-5` in batches when credentials are
available, and the answers are cached.

See `evaluation/evaluation_report.md` for metrics, custom cases, failures and fixes, and
`evaluation/usage_report.md` for token usage.
