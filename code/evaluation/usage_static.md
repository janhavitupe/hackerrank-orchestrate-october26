## Why the runtime token count is so low

The agent is **deterministic-first**. Identity resolution, evidence parsing (JSON, SQL, 7 log
dialects, handover text, PDFs via `pdftotext`), state reconstruction, policy and step ordering are
plain code, so they cost no tokens and give the same answer on every run. The LLM is used only where judgement
on free text is needed:

| Stage | Model | When it runs |
|---|---|---|
| Request intent ("does this text authorise deletion?") | `claude-opus-5-5`, effort `low`, up to 25 texts per call | Only for texts the multilingual rule classifier scores below 0.9 confidence; results are cached in `code/.cache/intent_cache.json` |
| Screenshot transcription | `claude-opus-5-5` (multimodal) | Once, during development; cached in `code/image_extractions.json` |

In the final run, 508 of the 518 requests matched an explicit deletion template with 0.95
confidence. The 10 non-deletion requests matched explicit negative patterns (correction, export,
access, opt-out, "do not close the account"). Seven of those 10 scored 0.7 and would have been sent
to the model, but the run had no Anthropic credentials (and no `anthropic` package installed),
so the classifier kept its rule verdicts. Those verdicts agree with the activity log's
`CLASSIFY_REQUEST` entries, which also list exactly 10 non-deletion requests.
To run the LLM pass, `pip install anthropic`, set `ANTHROPIC_API_KEY` and re-run. This report
regenerates itself.

## One-time multimodal extraction (development session, not part of the run)

The 11 screenshots under `dataset/evidence/images/` were read once by Claude Opus 5.5 inside the
Claude Code development session. The structured facts (resource id, stored identifiers,
references, state flags) were cached in `code/image_extractions.json`. Exact token counts were not
exposed by the session, so the figures below are **estimates**, using the image-token rule of thumb
`width x height / 750` and the length of the transcription:

| Item | Estimate |
|---|---:|
| Image input tokens (11 screens, 1500-1800 px wide) | ~29,000 |
| Instruction / context input tokens | ~2,000 |
| Transcription output tokens | ~3,500 |
| Estimated cost at $4 / $20 per 1M | ~$0.19 total, ~$0.0004 per request amortised over 518 |

## Overall

| Scope | Calls | Tokens | Est. cost |
|---|---:|---:|---:|
| Final full-dataset run (above) | see table | see table | see table |
| One-time image transcription (estimate) | 11 images | ~34,500 | ~$0.19 |
