#!/usr/bin/env node
/**
 * regenerate.mjs — the script that ships INSIDE an Atrekos assessment archive.
 *
 * #591 (the #119 M5 design, finally built). An archive is evidence handed to
 * someone outside the product: an auditor, a customer's security team, a
 * regulator. Until now they could read it and had no way to answer the two
 * questions that actually matter — "is this what was exported?", and "I have
 * edited the inputs; what does that contradict?"
 *
 * Run it with Node 24 and nothing else:
 *
 *     node regenerate.mjs [--archive <dir>]
 *
 * ## What it does, and the line it does not cross
 *
 * Two phases:
 *
 *   1. VERIFY — recompute the SHA-256 of every file against `manifest.json`.
 *   2. DIVERGE — for files under `input/` that have been edited, compare the
 *      authored values against the values the frozen `output/engine-result.json`
 *      recorded, and say which ones now contradict it.
 *
 * It does NOT run the engine, compute new risk values, or produce new reports.
 * That is a deliberate boundary, not a shortcoming: the engine is not in the
 * archive, and a script that guessed at new risk values would be manufacturing
 * exactly the kind of unverifiable claim this archive exists to avoid. Where a
 * consequence can only be known by re-running the assessment, the report says
 * so in those words.
 *
 * ## Read-only, absolutely
 *
 * The script never writes into the archive. Not a cache, not a report file,
 * not a fixed-up manifest. An approved archive is evidence: rewriting
 * `output/` would destroy the very hashes being verified, and any file it left
 * behind would make the NEXT run report an extra file and refuse. The report
 * goes to stdout and nowhere else.
 *
 * ## No network, no dependencies
 *
 * Node standard library only. Nothing here opens a socket. An archive is
 * opened on machines whose owners have every reason to distrust it, and the
 * only honest way to earn that is to need nothing.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { join, relative, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

/** The only archive schema this script understands. */
const SUPPORTED_SCHEMA_VERSION = 5;

/**
 * The files a recipient is invited to edit.
 *
 * Everything else — the `.json` snapshots, `output/`, `assets/`, the README —
 * is the shipped record. An edit there is an integrity failure, not an
 * analysis subject, and the difference is the whole reason this is a set
 * rather than a guess.
 */
const EDITABLE = /^input\/[^/]+\.yaml$/;

const EXIT = { OK: 0, INTEGRITY: 1, VERSION: 2, STRUCTURAL: 3 };

// ---------------------------------------------------------------------------
// A YAML parser for exactly the subset this archive emits
// ---------------------------------------------------------------------------

/**
 * The archive's YAML is produced by one function with one set of options, so
 * the shapes are known and small: block mappings, block sequences, plain and
 * quoted scalars, block literals for multi-line prose, and `[]` for an empty
 * list.
 *
 * Anything outside that fails loudly (exit 3) rather than being half-understood.
 * A parser that silently mis-reads a customer's edit would report a divergence
 * that is not there, or — far worse — miss one that is.
 */
class YamlError extends Error {
  constructor(message, line) {
    super(line === undefined ? message : `line ${line}: ${message}`);
    this.line = line;
  }
}

export function parseYaml(text) {
  const lines = [];
  // The raw lines stay available for block scalars: a `#` line or a blank line
  // inside a rationale is content, and the structural list below has already
  // lost both (#1757, finding 34).
  const rawLines = text.split('\n');
  rawLines.forEach((raw, i) => {
    const withoutComment = stripComment(raw);
    if (withoutComment.trim() === '') return; // blank and comment-only lines
    lines.push({ indent: raw.length - raw.trimStart().length, text: withoutComment.trimEnd(), no: i + 1 });
  });
  if (lines.length === 0) return null;

  const cursor = { i: 0, raw: rawLines };
  const value = parseBlock(lines, cursor, lines[0].indent);
  if (cursor.i < lines.length) {
    throw new YamlError('unexpected content after the document', lines[cursor.i].no);
  }
  return value;
}

/**
 * Strip a trailing `# comment`, respecting quotes.
 *
 * The builder emits no comments, but a recipient reading an archive may well
 * annotate what they edited — and losing their file to a `#` would be a poor
 * reward for engaging with it.
 */
function stripComment(raw) {
  let quote = null;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (quote) {
      if (ch === '\\' && quote === '"') i += 1;
      else if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '#' && (i === 0 || /\s/.test(raw[i - 1]))) {
      return raw.slice(0, i);
    }
  }
  return raw;
}

function parseBlock(lines, cursor, indent) {
  const line = lines[cursor.i];
  if (!line) return null;
  if (line.text.trimStart().startsWith('- ') || line.text.trim() === '-') {
    return parseSequence(lines, cursor, indent);
  }
  // A bare scalar document. `input/tracing.yaml` is literally `null` when no
  // paths were confirmed, so this is a shipped shape, not an edge case.
  if (!splitKey(line.text.slice(indent), line.no)) {
    cursor.i += 1;
    return parseScalar(line.text.slice(indent), line.no);
  }
  return parseMapping(lines, cursor, indent);
}

function parseSequence(lines, cursor, indent) {
  const out = [];
  while (cursor.i < lines.length && lines[cursor.i].indent === indent) {
    const line = lines[cursor.i];
    const body = line.text.slice(indent);
    if (!body.startsWith('-')) break;
    const rest = body.slice(1).replace(/^ /, '');
    cursor.i += 1;

    if (rest === '') {
      // `-` alone: the item is the indented block beneath it.
      out.push(
        cursor.i < lines.length && lines[cursor.i].indent > indent
          ? parseBlock(lines, cursor, lines[cursor.i].indent)
          : null,
      );
      continue;
    }

    // `- key: value` — the item is a mapping whose first key sits on this
    // line. Its remaining keys are indented to where that key started.
    const keyed = splitKey(rest, line.no);
    if (keyed) {
      const itemIndent = indent + (body.length - rest.length);
      const map = {};
      assignKey(map, keyed, lines, cursor, itemIndent, line.no);
      while (cursor.i < lines.length && lines[cursor.i].indent === itemIndent) {
        const next = lines[cursor.i];
        const nextKeyed = splitKey(next.text.slice(itemIndent), next.no);
        if (!nextKeyed) break;
        cursor.i += 1;
        assignKey(map, nextKeyed, lines, cursor, itemIndent, next.no);
      }
      out.push(map);
      continue;
    }

    out.push(parseScalar(rest, line.no));
  }
  return out;
}

function parseMapping(lines, cursor, indent) {
  const map = {};
  while (cursor.i < lines.length && lines[cursor.i].indent === indent) {
    const line = lines[cursor.i];
    const keyed = splitKey(line.text.slice(indent), line.no);
    if (!keyed) break;
    cursor.i += 1;
    assignKey(map, keyed, lines, cursor, indent, line.no);
  }
  return map;
}

/** `key: rest`, or null when the line is not a mapping entry. */
function splitKey(body, lineNo) {
  const match = /^(?:"((?:[^"\\]|\\.)*)"|'((?:[^']|'')*)'|([^:\s][^:]*?))\s*:(?:\s+(.*))?$/.exec(body);
  if (!match) return null;
  const key =
    match[1] !== undefined
      ? unescapeDouble(match[1], lineNo)
      : match[2] !== undefined
        ? match[2].replace(/''/g, "'")
        : match[3];
  return { key, rest: match[4] ?? '' };
}

function assignKey(map, { key, rest }, lines, cursor, indent, lineNo) {
  if (Object.prototype.hasOwnProperty.call(map, key)) {
    throw new YamlError(`duplicate key ${JSON.stringify(key)}`, lineNo);
  }
  if (rest.startsWith('|') || rest.startsWith('>')) {
    map[key] = readBlockScalar(lines, cursor, indent, rest, lineNo);
    return;
  }
  if (rest === '') {
    // The value is the indented block beneath this key — or nothing.
    map[key] =
      cursor.i < lines.length && lines[cursor.i].indent > indent
        ? parseBlock(lines, cursor, lines[cursor.i].indent)
        : cursor.i < lines.length && lines[cursor.i].indent === indent &&
            lines[cursor.i].text.slice(indent).startsWith('-')
          ? parseSequence(lines, cursor, indent)
          : null;
    return;
  }
  map[key] = parseScalar(rest, lineNo);
}

/**
 * A block scalar, read from the raw lines the way the `yaml` package reads it.
 *
 * Accepted headers: `|`, `|-`, `|+`, each with an optional indentation digit 1
 * to 9 before or after the chomp indicator (the emitter writes `|+` for a value
 * ending in two line breaks and `|2-` for one whose first line starts with a
 * space), plus `>` and `>-`. Anything else fails loudly, like every construct
 * outside the subset. Chomping: `-` strips every trailing line break, the plain
 * header keeps one, `+` keeps all. Folded keeps its old reading (newlines become
 * spaces, blank lines dropped); the archive does not emit it.
 *
 * `lineNo` is the header's 1-based line, so it is also the raw index of the
 * first line of the block.
 */
function readBlockScalar(lines, cursor, indent, header, lineNo) {
  const match = /^([|>])(?:([1-9])([-+])?|([-+])([1-9])?)?$/.exec(header);
  const style = match ? match[1] : null;
  const chomp = match ? (match[3] ?? match[4] ?? '') : '';
  const digit = match ? (match[2] ?? match[5]) : undefined;
  if (!match || (style === '>' && (digit !== undefined || chomp === '+'))) {
    throw new YamlError(`unsupported block scalar header ${JSON.stringify(header)}`, lineNo);
  }

  const raw = cursor.raw;
  // A file ending in a line break splits into a final empty element that is not
  // a line of the block.
  const end = raw.length > 0 && raw[raw.length - 1] === '' ? raw.length - 1 : raw.length;
  let blockIndent = digit === undefined ? null : indent + Number(digit);
  const content = [];
  let index = lineNo;
  for (; index < end; index += 1) {
    const line = raw[index];
    if (line.trim() === '') {
      content.push(blockIndent !== null && line.length > blockIndent ? line.slice(blockIndent) : '');
      continue;
    }
    const lineIndent = line.length - line.trimStart().length;
    if (lineIndent <= indent) break;
    if (blockIndent === null) blockIndent = lineIndent;
    if (lineIndent < blockIndent) {
      throw new YamlError('a block scalar line is indented less than its first line', index + 1);
    }
    content.push(line.slice(blockIndent));
  }
  // The structural lines inside the block (comment-stripped copies of what was
  // just read) are not structure.
  while (cursor.i < lines.length && lines[cursor.i].no <= index) cursor.i += 1;

  let trailing = 0;
  while (trailing < content.length && content[content.length - 1 - trailing] === '') trailing += 1;
  const body = content.slice(0, content.length - trailing);
  if (style === '>') {
    const folded = body.filter((l) => l !== '').join(' ');
    return chomp === '-' ? folded : `${folded}\n`;
  }
  if (chomp === '-') return body.join('\n');
  if (chomp === '+') return body.length === 0 ? '\n'.repeat(trailing) : `${body.join('\n')}\n${'\n'.repeat(trailing)}`;
  return body.length === 0 ? '' : `${body.join('\n')}\n`;
}

function parseScalar(raw, lineNo) {
  const text = raw.trim();
  if (text === '') return null;
  if (text === 'null' || text === '~') return null;
  if (text === 'true') return true;
  if (text === 'false') return false;
  if (text === '[]') return [];
  if (text === '{}') return {};
  if (text.startsWith('"')) {
    if (!text.endsWith('"') || text.length < 2) {
      throw new YamlError('unterminated double-quoted string', lineNo);
    }
    return unescapeDouble(text.slice(1, -1), lineNo);
  }
  if (text.startsWith("'")) {
    if (!text.endsWith("'") || text.length < 2) {
      throw new YamlError('unterminated single-quoted string', lineNo);
    }
    return text.slice(1, -1).replace(/''/g, "'");
  }
  if (text.startsWith('[') || text.startsWith('{')) {
    // Non-empty flow collections are outside the emitted subset. Refusing is
    // the point — a hand-rolled flow parser is how a value gets mis-read.
    throw new YamlError('inline lists and maps are not supported here', lineNo);
  }
  if (/^-?\d+$/.test(text)) return Number.parseInt(text, 10);
  if (/^-?\d*\.\d+$/.test(text)) return Number.parseFloat(text);
  return text;
}

function unescapeDouble(body, lineNo) {
  return body.replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (_m, esc) => {
    if (esc[0] === 'u' || esc[0] === 'x') {
      return String.fromCharCode(Number.parseInt(esc.slice(1), 16));
    }
    const simple = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', '/': '/', '0': '\0' }[esc];
    if (simple === undefined) throw new YamlError(`unknown escape \\${esc}`, lineNo);
    return simple;
  });
}

// ---------------------------------------------------------------------------
// Phase 1 — verification
// ---------------------------------------------------------------------------

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

/**
 * Every entry of the tree, as `{ path, kind }`: `file` for a regular file and `other` for anything else (a symbolic link, a FIFO, a
 * socket, a device). A `Dirent` reports the entry's OWN type, so a link is never followed and no target is read.
 *
 * #1881: only regular files used to be returned, so a link added to the archive was invisible: never `EXTRA`, and the run could
 * print "Every file matches" for a tree that held a link to anything.
 */
function walk(root, base = root) {
  const out = [];
  for (const entry of readdirSync(base, { withFileTypes: true })) {
    const full = join(base, entry.name);
    if (entry.isDirectory()) out.push(...walk(root, full));
    else out.push({ path: relative(root, full).split(sep).join('/'), kind: entry.isFile() ? 'file' : 'other' });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/**
 * Compare the tree on disk against `manifest.files[]`.
 *
 * `manifest.json` is written after the hashing pass, so it is not listed in
 * its own `files[]` — a verifier that expected it there would report the
 * manifest as an extra file on every honest archive.
 *
 * States beyond the hash: `NOTFILE` (a listed path whose entry is a link or a special file), `UNREADABLE` (a listed regular file whose
 * read failed: not a finding about the archive, so it is reported on its own and does not read as tampering).
 */
function verify(root, manifest) {
  const expected = new Map(manifest.files.map((f) => [f.path, f]));
  const found = new Map(walk(root).map((e) => [e.path, e.kind]));
  const present = new Set([...found.keys()].filter((p) => p !== 'manifest.json'));

  const results = [];
  // The manifest is read by path, which follows a link: a manifest that is not a regular file is not the file that was exported.
  if (found.get('manifest.json') === 'other') results.push({ path: 'manifest.json', state: 'NOTFILE' });
  for (const [path, entry] of expected) {
    if (!present.has(path)) {
      results.push({ path, state: 'MISSING' });
      continue;
    }
    if (found.get(path) !== 'file') {
      results.push({ path, state: 'NOTFILE' });
      continue;
    }
    let actual;
    try {
      actual = sha256(readFileSync(join(root, path)));
    } catch (err) {
      results.push({ path, state: 'UNREADABLE', detail: err.message });
      continue;
    }
    results.push({
      path,
      state: actual === entry.sha256 ? 'ok' : EDITABLE.test(path) ? 'EDITED' : 'CHANGED',
    });
  }
  for (const path of present) {
    if (!expected.has(path)) results.push({ path, state: 'EXTRA' });
  }
  return results.sort((a, b) => a.path.localeCompare(b.path));
}

// ---------------------------------------------------------------------------
// Phase 2 — divergence against the frozen engine result
// ---------------------------------------------------------------------------

/**
 * Where each authored field is echoed in `output/engine-result.json`.
 *
 * This is the honest half of the script. For each editable file it says which
 * authored fields the frozen result records — and, just as importantly, which
 * it does not. A field with no echo is REPORTED as unverifiable, never
 * skipped: silence reads as "checked, fine", and in a compliance workflow
 * that is a lie by omission.
 */
const ECHO = {
  'input/answers.yaml': {
    key: 'questionCode',
    label: (row) => `answers[questionCode=${row.questionCode}]`,
    fields: {
      rationale: (row, result) =>
        find(result.answerRationales, (r) => r.questionCode === row.questionCode)?.rationale,
      answer1: null,
      answer2: null,
      needsReview: null,
      questionCode: (row, result) =>
        find(result.activeQuestions, (q) => q.code === row.questionCode)
          ? row.questionCode
          : undefined,
    },
  },
  // #1881: the lookups read the shapes a real archive's `output/engine-result.json` carries (the rich export): a treatment is
  // `{ riskId, treatment, treatmentRationale? }` (the person's decision and rationale, flattened from the engine's `callerOverride`),
  // and quality indicators are the `quality[]` list whose accepted items carry `accepted: { acceptedBy, rationale }`. The lookups
  // named containers the export never emits (`callerOverride`, `qualityIndicators`), so on a real archive every edit read "no echo".
  'input/treatments.yaml': {
    key: 'riskId',
    label: (row) => `treatments[riskId=${row.riskId}]`,
    fields: {
      decision: (row, result) => find(result.treatments, (t) => t.riskId === row.riskId)?.treatment,
      rationale: (row, result) => {
        const t = find(result.treatments, (x) => x.riskId === row.riskId);
        return t ? (t.treatmentRationale ?? null) : undefined;
      },
      riskId: null,
    },
    // What the shipped result records that a removed row would contradict: a decision no proposal can be (a proposal is only
    // `accept` or `manual`, so avoid, mitigate and transfer are a person's), or any rationale. An `accept` with no rationale cannot
    // be told from the engine's own proposal and is not reported.
    recorded: (result) =>
      (Array.isArray(result.treatments) ? result.treatments : [])
        .filter((t) => ['avoid', 'mitigate', 'transfer'].includes(t.treatment) || Boolean(t.treatmentRationale))
        .map((t) => ({
          key: t.riskId,
          fields: { decision: t.treatment, ...(t.treatmentRationale ? { rationale: t.treatmentRationale } : {}) },
        })),
  },
  'input/qi-acceptances.yaml': {
    key: 'qiCode',
    label: (row) => `qi-acceptances[qiCode=${row.qiCode}]`,
    fields: {
      rationale: (row, result) => {
        const qi = qualityItem(result, row.qiCode);
        return qi ? (qi.accepted?.rationale ?? null) : undefined;
      },
      acceptedCount: (row, result) => {
        const qi = qualityItem(result, row.qiCode);
        return qi ? (qi.accepted?.acceptedBy?.length ?? 0) : undefined;
      },
      qiCode: null,
    },
    recorded: (result) =>
      (Array.isArray(result.quality) ? result.quality : [])
        .filter((q) => q.accepted)
        .map((q) => ({
          key: q.code,
          fields: {
            ...(q.accepted.rationale ? { rationale: q.accepted.rationale } : {}),
            ...(Array.isArray(q.accepted.acceptedBy) ? { acceptedCount: q.accepted.acceptedBy.length } : {}),
          },
        })),
  },
  // These three have no verified echo anywhere in the frozen result. They are
  // listed — with every field mapped to null — precisely so their edits are
  // reported as unverifiable rather than quietly passing.
  'input/mitigations.yaml': { key: 'attackStepCode', label: (row) => `mitigations[attackStepCode=${row.attackStepCode}]`, fields: {} },
  'input/toe.yaml': { key: null, label: () => 'toe', fields: {} },
  'input/tracing.yaml': { key: null, label: () => 'tracing', fields: {} },
};

const find = (list, predicate) => (Array.isArray(list) ? list.find(predicate) : undefined);

const qualityItem = (result, qiCode) => find(result.quality, (q) => q.code === qiCode);

/** One report row per authored field of an edited file. */
export function diverge(path, parsed, result) {
  const spec = ECHO[path];
  if (!spec) return [{ field: path, state: 'no-echo' }];

  const rows = Array.isArray(parsed) ? parsed : [parsed];
  const out = [];
  for (const row of rows) {
    if (row === null || typeof row !== 'object') continue;
    for (const field of Object.keys(row).sort()) {
      const lookup = spec.fields[field];
      const label = `${spec.label(row)}.${field}`;
      if (typeof lookup !== 'function') {
        out.push({ field: label, state: 'no-echo', value: row[field] });
        continue;
      }
      const frozen = lookup(row, result);
      if (frozen === undefined) {
        out.push({ field: label, state: 'no-echo', value: row[field] });
      } else if (same(frozen, row[field])) {
        out.push({ field: label, state: 'match', value: row[field] });
      } else {
        out.push({ field: label, state: 'divergence', value: row[field], frozen });
      }
    }
  }

  // #1881: the other direction. A line the shipped result records and the edited file no longer has (a row removed, a field's line
  // deleted, the file emptied) contradicts the result as surely as a changed value, and used to produce no row at all.
  if (typeof spec.recorded === 'function') {
    const byKey = new Map();
    for (const row of rows) {
      if (row !== null && typeof row === 'object' && !byKey.has(row[spec.key])) byKey.set(row[spec.key], row);
    }
    for (const record of spec.recorded(result)) {
      const label = spec.label({ [spec.key]: record.key });
      const row = byKey.get(record.key);
      if (!row) {
        out.push({ field: `${label} (row removed)`, state: 'divergence', value: undefined, frozen: record.fields });
        continue;
      }
      for (const [name, frozen] of Object.entries(record.fields)) {
        if (!(name in row)) out.push({ field: `${label}.${name}`, state: 'divergence', value: undefined, frozen });
      }
    }
  }
  return out;
}

const same = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

const show = (v) =>
  v === null || v === undefined
    ? '(none)'
    : typeof v === 'string'
      ? JSON.stringify(v.length > 120 ? `${v.slice(0, 117)}…` : v)
      : JSON.stringify(v);

/**
 * #1761 M3: compare the manifest's `evidenceStatus` and approval with `provenance.json`, the only record of them that
 * the file hashes cover. States: `agrees`; `absent` (no provenance.json in files[] — older archives); `disagrees`;
 * `unreadable` (listed, hash-checked, but not JSON). A listed file that is MISSING or CHANGED is already reported by
 * the hash check, so it is `agrees` here: that report stops the run before this result is used.
 */
function crossCheckProvenance(root, manifest, results) {
  const listed = manifest.files.some((f) => f?.path === 'provenance.json');
  if (!listed) return { state: 'absent' };
  if (results.find((r) => r.path === 'provenance.json')?.state !== 'ok') return { state: 'agrees' };

  let provenance;
  try {
    provenance = JSON.parse(readFileSync(join(root, 'provenance.json'), 'utf8'));
  } catch (err) {
    return { state: 'unreadable', lines: [`provenance.json could not be read: ${err.message}`] };
  }

  const lines = [];
  if (provenance?.evidenceStatus !== manifest.evidenceStatus) {
    lines.push(
      `evidence status: manifest.json says ${show(manifest.evidenceStatus)}, provenance.json says ${show(provenance?.evidenceStatus)}`,
    );
  }
  const manifestApproved = Boolean(manifest.approvedAt);
  const approval = provenance?.approval;
  const provenanceApproved = approval !== null && approval !== undefined;
  if (manifestApproved !== provenanceApproved) {
    lines.push(
      `approval: manifest.json ${manifestApproved ? `records one at ${show(manifest.approvedAt)}` : 'records none'}, provenance.json ${provenanceApproved ? 'records one' : 'records none'}`,
    );
  } else if (manifestApproved && typeof approval?.approvedAt === 'string' && approval.approvedAt !== manifest.approvedAt) {
    lines.push(
      `approval time: manifest.json says ${show(manifest.approvedAt)}, provenance.json says ${show(approval.approvedAt)}`,
    );
  }
  if (lines.length === 0) return { state: 'agrees' };
  return {
    state: 'disagrees',
    lines: [
      'manifest.json disagrees with provenance.json, which the file hashes cover:',
      ...lines.map((l) => `  ${l}`),
      'The manifest is not hashed by anything, so a change there goes unnoticed by the file check. Do not rely on the status it shows.',
    ],
  };
}

export function main(argv) {
  const flag = argv.indexOf('--archive');
  const root = flag === -1 ? dirname(fileURLToPath(import.meta.url)) : argv[flag + 1];
  if (flag !== -1 && !root) return fail(EXIT.STRUCTURAL, '--archive needs a directory');

  // #1761 M3: the hash of manifest.json as the recipient received it from the exporter, by a channel other than
  // this archive. Without it the script can only say the files agree with the manifest, not that the manifest is
  // the exported one.
  const expectFlag = argv.indexOf('--expect-manifest-sha256');
  const expected = expectFlag === -1 ? null : argv[expectFlag + 1];
  if (expectFlag !== -1 && !/^[0-9a-fA-F]{64}$/.test(expected ?? '')) {
    return fail(EXIT.STRUCTURAL, '--expect-manifest-sha256 needs the 64 hexadecimal characters of a SHA-256');
  }

  let manifest;
  let manifestHash;
  try {
    const manifestBytes = readFileSync(join(root, 'manifest.json'));
    manifestHash = sha256(manifestBytes);
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (err) {
    return fail(EXIT.STRUCTURAL, `manifest.json could not be read: ${err.message}`);
  }
  if (!manifest || !Array.isArray(manifest.files)) {
    return fail(EXIT.STRUCTURAL, 'manifest.json has no files[] — this is not an Atrekos archive');
  }

  // Version first, before anything is read or reported: a newer archive may
  // mean things this script would describe wrongly, and a wrong description of
  // evidence is worse than none.
  if (manifest.archiveSchemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    const newer =
      typeof manifest.archiveSchemaVersion === 'number' &&
      manifest.archiveSchemaVersion > SUPPORTED_SCHEMA_VERSION;
    return fail(
      EXIT.VERSION,
      newer
        ? [
            `This archive is newer than this script (schema ${manifest.archiveSchemaVersion}, this script understands ${SUPPORTED_SCHEMA_VERSION}).`,
            'Checking it here would mislead you. Use the script that shipped with it.',
          ]
        : `Unrecognised archive schema version: ${JSON.stringify(manifest.archiveSchemaVersion)}.`,
    );
  }

  // The files are checked before the header, so the header never states a status the hashed record contradicts.
  const results = verify(root, manifest);
  const crossCheck = crossCheckProvenance(root, manifest, results);
  const statusNote =
    crossCheck.state === 'disagrees'
      ? ' (DISPUTED: provenance.json says otherwise, see below)'
      : crossCheck.state === 'absent'
        ? ' (not cross-checked)'
        : '';

  // --- Header ---
  const reopened = manifest.evidenceStatus === 'working-copy' && Boolean(manifest.approvedAt);
  print(`Atrekos assessment archive — verification report`);
  print(`  schema version : ${manifest.archiveSchemaVersion}`);
  print(`  engine version : ${manifest.engineVersion}`);
  print(`  evidence status: ${manifest.evidenceStatus}${statusNote}`);
  if (manifest.approvedAt) print(`  approved at    : ${manifest.approvedAt}${statusNote}`);
  if (reopened) {
    print('');
    print('  NOTE: this assessment was signed off and then REOPENED. The frozen');
    print('  documents under output/ predate the exported input/, so differences');
    print('  below may date from that reopening rather than from anything you');
    print('  edited. They are stated as differences from the frozen sign-off');
    print('  output, not as consequences of your changes.');
  }

  // --- Phase 1 ---
  print('');
  print('Verification');
  for (const r of results) {
    print(`  ${r.state === 'ok' ? 'ok     ' : `${r.state}`.padEnd(7)} ${r.path}`);
  }

  // #1761 M3: always said, so a recipient can compare it with the one the exporter gave them.
  print('');
  print(`manifest.json sha256: ${manifestHash}`);
  if (expected !== null && expected.toLowerCase() !== manifestHash) {
    print('');
    print('The manifest in this archive is not the one you were given.');
    print(`  you gave    : ${expected.toLowerCase()}`);
    print(`  this archive: ${manifestHash}`);
    print('Whoever passed it on may have changed it, files and manifest together. Do not rely on it.');
    return EXIT.INTEGRITY;
  }

  const broken = results.filter((r) => ['MISSING', 'CHANGED', 'EXTRA', 'NOTFILE'].includes(r.state));
  if (broken.length > 0) {
    print('');
    print('These files are not as exported:');
    for (const r of broken) {
      print(
        `  ${r.path} — ${
          r.state === 'MISSING'
            ? 'listed in the manifest but not present'
            : r.state === 'EXTRA'
              ? 'present but not listed in the manifest'
              : r.state === 'NOTFILE'
                ? 'present, but not a regular file (a link or a special file)'
                : 'contents differ, and this file is part of the shipped record (not an input you are invited to edit)'
        }`,
      );
    }
    print('');
    print('No further analysis was done: an archive that is not intact cannot be');
    print('reasoned about. Re-export it, or compare against the copy you were sent.');
    return EXIT.INTEGRITY;
  }

  // #1881: a listed file that could not be read says nothing about the archive: it is a failure to read, not an integrity finding.
  const unreadable = results.filter((r) => r.state === 'UNREADABLE');
  if (unreadable.length > 0) {
    print('');
    for (const r of unreadable) print(`${r.path}: could not be read: ${r.detail}`);
    print('The files that could be read were checked; this archive could not be checked in full.');
    return EXIT.STRUCTURAL;
  }

  // #1761 M3: the manifest's status and approval time are not hashed by anything; provenance.json is (it is listed
  // in files[] and was just checked), so the two are compared.
  if (crossCheck.state === 'disagrees' || crossCheck.state === 'unreadable') {
    print('');
    for (const line of crossCheck.lines) print(line);
    return crossCheck.state === 'disagrees' ? EXIT.INTEGRITY : EXIT.STRUCTURAL;
  }
  if (crossCheck.state === 'absent') {
    print('');
    print('No provenance record in this archive, so the status above is not cross-checked.');
  }

  const edited = results.filter((r) => r.state === 'EDITED');
  if (edited.length === 0) {
    print('');
    if (expected !== null) {
      print('The manifest matches the hash you gave, and every file matches the manifest.');
      print('This archive is byte-for-byte what was exported.');
    } else {
      print('No changes. Every file matches the manifest in this archive.');
      print('The manifest itself is not signed, so this does not show the archive is what was exported.');
      print('To check it, compare the manifest hash above with one you received separately.');
    }
    return EXIT.OK;
  }

  // --- Phase 2 ---
  let result;
  try {
    result = JSON.parse(readFileSync(join(root, 'output/engine-result.json'), 'utf8'));
  } catch (err) {
    print('');
    return fail(
      EXIT.STRUCTURAL,
      [
        'Hashes were checked, but output/engine-result.json could not be read, so the',
        `consequences of your edits cannot be reported: ${err.message}`,
      ],
    );
  }

  print('');
  print('Edits');
  for (const r of edited) {
    let parsed;
    try {
      parsed = parseYaml(readFileSync(join(root, r.path), 'utf8'));
    } catch (err) {
      print('');
      return fail(EXIT.STRUCTURAL, `${r.path}: ${err.message}`);
    }
    print('');
    print(`  ${r.path}`);
    for (const row of diverge(r.path, parsed, result)) {
      if (row.state === 'match') {
        print(`    match       ${row.field} = ${show(row.value)}`);
      } else if (row.state === 'divergence') {
        print(`    DIVERGENCE  ${row.field}`);
        print(`                you have    : ${show(row.value)}`);
        print(`                shipped with: ${show(row.frozen)}`);
      } else {
        print(`    no echo     ${row.field} — the shipped documents cannot confirm or`);
        print(`                deny this value; nothing in output/ records it.`);
      }
    }
  }

  // --- Caveats ---
  print('');
  print('What this does and does not tell you');
  print('  - Hashes above are recomputed from the files on disk. That part is exact.');
  print('  - Differences are against the engine output frozen in output/. This script');
  print('    does NOT run the engine, so it cannot tell you the NEW risk values, RAP');
  print('    classes or verdicts your edits would produce. Only re-running the');
  print('    assessment can do that.');
  print('  - A field reported as "no echo" is not a field that passed. It is a field');
  print('    the shipped documents do not record, so nothing here can check it.');
  print('  - A row you removed is reported only where the shipped result records it. A treatment of');
  print('    "accept" with no rationale cannot be told from the engine\'s own proposal, so removing one');
  print('    is not reported.');
  if (reopened) {
    print('  - This archive was reopened after sign-off (see the note above).');
  }
  return EXIT.OK;
}

/**
 * #1761 M3: the one place that writes to the terminal. A manifest value, a file name or a message that echoes input
 * can carry control characters (an escape sequence rewrites what was already printed, CR overwrites a line, the
 * bidirectional controls reorder it), so each is shown as a visible `\u{XX}` instead. Exactly one LF is appended; a
 * caller wanting several lines makes several calls.
 */
// eslint-disable-next-line no-control-regex -- the point is to find them
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;
const escapeControls = (text) =>
  String(text).replace(UNSAFE, (c) => `\\u{${c.codePointAt(0).toString(16).toUpperCase().padStart(2, '0')}}`);

function print(line) {
  process.stdout.write(`${escapeControls(line)}\n`);
}

/** `message` is a line, or an array of lines when the text has several. */
function fail(code, message) {
  for (const line of Array.isArray(message) ? message : [message]) print(line);
  return code;
}

/*
 * Run only when executed, not when imported.
 *
 * The repo's test suite imports this file to exercise the parser directly —
 * against the very YAML the builder emits — which is the only way to prove the
 * subset is adequate rather than assumed. An unconditional call here would
 * make the module run (and set an exit code) merely from being imported.
 */
function isMain() {
  if (!process.argv[1]) return false;
  // Compared through realpath: on macOS the temp directory a recipient (or a
  // test) unpacks into is `/var/...` while `import.meta.url` resolves to
  // `/private/var/...`, and a raw string compare silently decides the script
  // is not the entry point — so it would run, print nothing, and exit 0.
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1]);
  } catch {
    return false;
  }
}

if (isMain()) {
  process.exitCode = main(process.argv.slice(2));
}
