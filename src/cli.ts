#!/usr/bin/env node
/**
 * cxf — CLI for the FIDO Credential Exchange Format.
 *
 *   cxf validate <file> [--json]   conformance-check a CXF export
 *   cxf inspect  <file> [--json]   summarize a CXF export (never prints values)
 *
 * Exit codes: 0 conforms / inspected (warnings allowed), 1 validation
 * errors, 2 unusable input or usage error.
 */

import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { CxfParseError, type Diagnostic } from "./diagnostics.js";
import { parseCxf, type CxfDocument } from "./parse.js";
import { validateDocument } from "./validate.js";
import type { Collection, Header } from "./types.js";

const USAGE = `Usage: cxf <command> <file> [options]

Commands:
  validate <file>   Check a CXF document or export archive for conformance.
  inspect <file>    Summarize contents. Secret values are never printed.

Options:
  --json            Machine-readable output.
  -h, --help        Show this help.

Exit codes: 0 ok, 1 validation errors, 2 unusable input.`;

export function main(argv: string[]): number {
  let args;
  try {
    args = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: "boolean", default: false },
        help: { type: "boolean", short: "h", default: false },
      },
    });
  } catch (e) {
    console.error(e instanceof Error ? e.message : String(e));
    console.error(USAGE);
    return 2;
  }

  const [command, file] = args.positionals;
  if (args.values.help || command === undefined) {
    console.log(USAGE);
    return args.values.help ? 0 : 2;
  }
  if (command !== "validate" && command !== "inspect") {
    console.error(`Unknown command "${command}".\n\n${USAGE}`);
    return 2;
  }
  if (file === undefined) {
    console.error(`cxf ${command} requires a file argument.\n\n${USAGE}`);
    return 2;
  }

  let bytes: Uint8Array;
  try {
    bytes = readFileSync(file);
  } catch (e) {
    console.error(`Cannot read ${file}: ${e instanceof Error ? e.message : String(e)}`);
    return 2;
  }

  let doc: CxfDocument;
  try {
    doc = parseCxf(bytes);
  } catch (e) {
    if (e instanceof CxfParseError) {
      if (args.values.json) {
        console.log(JSON.stringify({ file, ok: false, parseError: { code: e.code, message: e.message } }, null, 2));
      } else {
        console.error(`${file}: unusable input\n  ${e.message}`);
      }
      return 2;
    }
    throw e;
  }

  return command === "validate" ? runValidate(file, doc, args.values.json) : runInspect(file, doc, args.values.json);
}

function runValidate(file: string, doc: CxfDocument, json: boolean): number {
  const diagnostics = validateDocument(doc);
  const errors = diagnostics.filter((d) => d.severity === "error");
  const warnings = diagnostics.filter((d) => d.severity === "warning");

  if (json) {
    console.log(
      JSON.stringify(
        { file, ok: errors.length === 0, errors: errors.length, warnings: warnings.length, diagnostics },
        null,
        2,
      ),
    );
    return errors.length === 0 ? 0 : 1;
  }

  console.log(`${file}: ${errors.length} error(s), ${warnings.length} warning(s)`);
  for (const d of diagnostics) {
    console.log(`\n  ${d.severity} ${d.code} at ${d.path}`);
    console.log(`    ${d.message}`);
  }
  console.log(
    errors.length === 0
      ? `\nOK: document conforms to CXF v1.0${warnings.length > 0 ? ` (${warnings.length} warning(s))` : ""}.`
      : `\nFAIL: ${errors.length} conformance error(s).`,
  );
  return errors.length === 0 ? 0 : 1;
}

function countCollections(collections: Collection[]): number {
  let n = 0;
  for (const c of collections) {
    n += 1 + countCollections(Array.isArray(c.subCollections) ? c.subCollections : []);
  }
  return n;
}

function summarize(header: Header, doc: CxfDocument) {
  return {
    exporter: { rpId: header.exporterRpId, displayName: header.exporterDisplayName },
    version: header.version,
    exportedAt:
      typeof header.timestamp === "number" && Number.isFinite(header.timestamp)
        ? new Date(header.timestamp * 1000).toISOString()
        : "(invalid timestamp)",
    source: doc.source,
    archiveFiles:
      doc.source === "archive"
        ? { count: doc.files.size, totalBytes: [...doc.files.values()].reduce((s, f) => s + f.byteLength, 0) }
        : undefined,
    accounts: header.accounts.map((a) => {
      const histogram: Record<string, number> = {};
      for (const item of Array.isArray(a.items) ? a.items : []) {
        for (const cred of Array.isArray(item.credentials) ? item.credentials : []) {
          const type = typeof cred.type === "string" ? cred.type : "(untyped)";
          histogram[type] = (histogram[type] ?? 0) + 1;
        }
      }
      return {
        id: a.id,
        username: a.username,
        email: a.email,
        items: Array.isArray(a.items) ? a.items.length : 0,
        collections: countCollections(Array.isArray(a.collections) ? a.collections : []),
        credentials: histogram,
      };
    }),
  };
}

function runInspect(file: string, doc: CxfDocument, json: boolean): number {
  const s = summarize(doc.header, doc);
  if (json) {
    console.log(JSON.stringify({ file, ...s }, null, 2));
    return 0;
  }

  console.log(`${file}`);
  console.log(
    `  Exporter:  ${s.exporter.displayName} (${s.exporter.rpId}), CXF ${s.version?.major}.${s.version?.minor}`,
  );
  console.log(`  Exported:  ${s.exportedAt}`);
  console.log(`  Source:    ${s.source === "archive" ? `ZIP archive, ${s.archiveFiles?.count} file payload(s), ${s.archiveFiles?.totalBytes} byte(s)` : "bare JSON document"}`);
  console.log(`  Accounts:  ${s.accounts.length}`);
  for (const a of s.accounts) {
    console.log(`\n  Account ${a.username} <${a.email}> (id ${a.id})`);
    console.log(`    Items: ${a.items}   Collections: ${a.collections}`);
    const entries = Object.entries(a.credentials).sort(([x], [y]) => x.localeCompare(y));
    if (entries.length === 0) {
      console.log("    Credentials: none");
      continue;
    }
    console.log("    Credentials:");
    const width = Math.max(...entries.map(([t]) => t.length));
    for (const [type, count] of entries) {
      console.log(`      ${type.padEnd(width)}  ${count}`);
    }
  }
  return 0;
}

process.exitCode = main(process.argv.slice(2));
