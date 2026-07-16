/**
 * Parsing a CXF export: bare JSON document or ZIP export archive.
 *
 * The parser is deliberately lossless and minimal: it decodes, gates on the
 * few things without which no CXF document exists (valid JSON, object root,
 * accounts array), and returns the data untouched. The `Header` it returns is
 * a structural claim, not a verified one — run `validate()` (CXF2xxx
 * diagnostics) to establish conformance. Splitting it this way keeps a single
 * source of truth for every rule and guarantees parse -> serialize round-trips
 * never drop content the kit doesn't understand.
 */

import { isZipArchive, readArchive, type ArchiveLimits } from "./archive.js";
import { decodeUtf8Strict } from "./bytes.js";
import { CxfParseError } from "./diagnostics.js";
import type { Header } from "./types.js";

export interface CxfDocument {
  header: Header;
  /**
   * File-credential payloads keyed by File.id. Populated only when the input
   * was an export archive; empty for bare JSON documents.
   */
  files: Map<string, Uint8Array>;
  source: "json" | "archive";
}

export interface ParseOptions {
  /** Decompression caps for ZIP input (zip-bomb defense). */
  archiveLimits?: ArchiveLimits | undefined;
}

/**
 * Parse a CXF export from a JSON string, JSON bytes, or ZIP archive bytes
 * (sniffed by magic number). Byte input must be valid UTF-8 (CXF1007).
 */
export function parseCxf(input: string | Uint8Array, options: ParseOptions = {}): CxfDocument {
  if (typeof input !== "string" && isZipArchive(input)) {
    const { indexJson, files } = readArchive(input, options.archiveLimits ?? {});
    return { header: parseHeaderJson(indexJson), files, source: "archive" };
  }

  const text = typeof input === "string" ? input : decodeUtf8Strict(input, "Input");
  return { header: parseHeaderJson(text), files: new Map(), source: "json" };
}

function parseHeaderJson(text: string): Header {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch (cause) {
    throw new CxfParseError("CXF1001", "Input is not valid JSON.", { cause });
  }

  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    throw new CxfParseError(
      "CXF1002",
      `A CXF document's root must be a JSON object, got ${rootKind(root)}.`,
    );
  }
  if (!Array.isArray((root as { accounts?: unknown }).accounts)) {
    throw new CxfParseError(
      "CXF1005",
      'Root object has no "accounts" array; this is not a CXF Header document.',
    );
  }

  return root as Header;
}

function rootKind(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return `a ${typeof value}`;
}
