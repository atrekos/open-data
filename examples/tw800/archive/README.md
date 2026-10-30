# Atrekos assessment archive — Substation Cellular Router (TW800 Series)

## What is in here

| Folder | What it holds |
|---|---|
| `input/` | What was entered: answers, mitigations, treatments, quality acceptances, the TOE, and the catalog and model snapshots this assessment is pinned to. YAML files are meant to be read and edited; the `.json` snapshots are hashed inputs. |
| `output/` | What the engine produced: the reports, the traceability workbook, and `engine-result.json`. **Regenerated, not hand-edited** — an edit here would disagree with `input/` and with the manifest. |
| `assets/` | Every binary attachment, referenced from `input/toe.yaml`. |
| `manifest.json` | A SHA-256 for every file, the engine version, the input hash and the pinned versions. |
| `provenance.json` | Internal identifiers. Nothing else in the archive contains them; delete it and the rest still stands. |

The assets, interfaces, revision and organisation named in `input/` and `output/` are local keys (`asset-1`,
`interface-1`, `revision-1`, `organisation`) that mean something inside this archive only. `localKeys` in
`provenance.json` says which identifier each stands for.

## Reading it

Start with `output/reports/assessment-report.pdf` for the narrative. `input/answers.yaml`
is the questionnaire as answered, keyed by the same question codes the reports cite.
`output/traceability.xlsx` maps each risk back to the answers and steps that produced it.

## Checking it

Every file is listed in `manifest.json` with its SHA-256. Recomputing them shows that the
files agree with the manifest. The manifest is not signed, so that alone does not show this
archive is what was exported: compare the SHA-256 of `manifest.json` (the script below prints
it) with one you received separately, or give it as `--expect-manifest-sha256 <hash>`.

## Regenerating it

```
node regenerate.mjs
```

Node 24, no installation, no network access, no dependencies. The script is
**read-only** — it writes nothing into this archive.

It does two things:

1. Recomputes every hash against `manifest.json` and tells you which files, if
   any, differ. Editing anything outside the `input/*.yaml` files is reported as
   an integrity failure and stops the run — those files are the shipped record.
   So is a link or a special file inside the archive: only regular files belong
   in it, and a link is never followed.
2. For `input/*.yaml` files you have edited, compares what you wrote against the
   values recorded in `output/engine-result.json` and reports each authored field
   as matching, diverging, or having nothing in the shipped documents to check it
   against. A row you removed is reported too, where the shipped result records it.

It does **not** run the engine, produce new reports, or compute new risk values —
the engine is not in this archive. Where a consequence can only be known by
re-running the assessment, the report says so rather than guessing.

Exit codes: `0` report produced, `1` files are not as exported, `2` archive is
newer than the script, `3` something could not be read or parsed.
