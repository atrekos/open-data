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

Every file is listed in `manifest.json` with its SHA-256. Recomputing them shows that the files agree with
the manifest, and nothing more. To check the archive itself, in this order:

1. **Before running anything from this archive**, know that it is not signed. Nothing in it, this README
   and the script included, can prove the archive is what was exported: whoever changed it could have
   changed those too.
2. Get the SHA-256 of `manifest.json` from the person or system that exported it, **by a different route
   than this archive** (not from a file inside it).
3. Compute the SHA-256 of `manifest.json` with a tool you already have, not with anything from the
   archive: `shasum -a 256 manifest.json`, `sha256sum manifest.json`, or
   `certutil -hashfile manifest.json SHA256`. Compare it with the one you were given. **If they differ,
   stop.**
4. Compute the SHA-256 of `regenerate.mjs` the same way and compare it with its entry in `manifest.json`.
   **If they differ, stop.**
5. Only then run `node regenerate.mjs` (optionally with `--expect-manifest-sha256 <hash>`, as a second
   check of the hash you were given). The script runs with your user's privileges; read it first if you
   can.

If you have no hash from a separate route, the archive cannot be shown authentic.

## Regenerating it

```
node regenerate.mjs
```

Node 24, no installation, no network access, no dependencies. The script is
**read-only** — it writes nothing into this archive. (As shipped, when step 4 above passed.)

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
