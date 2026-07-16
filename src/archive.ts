/**
 * cxf-kit's export-archive convention. The CXF spec defines only the JSON
 * payload and no on-disk packaging (SPEC_NOTES #1), so this layout is
 * kit-defined:
 *
 *   export.cxf (ZIP)
 *   ├── index.json          the CXF Header document
 *   └── documents/<fileId>  bytes for each File credential, named by its id
 *
 * Hardening: decompression is capped (zip bombs -> CXF1006) and documents/
 * entry names must be pure base64url (no path separators or "..", so ids are
 * safe to use as filenames if a consumer extracts them to disk -> CXF1008).
 */

import { unzipSync, zipSync } from "fflate";
import { decodeUtf8Strict } from "./bytes.js";
import { CxfParseError } from "./diagnostics.js";

export const ARCHIVE_INDEX = "index.json";
export const ARCHIVE_DOCUMENTS_PREFIX = "documents/";

const FILE_ID_RE = /^[A-Za-z0-9_-]+$/;

export interface ArchiveLimits {
  /** Maximum number of entries in the archive. Default 10,000. */
  maxFiles?: number | undefined;
  /** Maximum total decompressed bytes across all entries. Default 1 GiB. */
  maxTotalBytes?: number | undefined;
}

const DEFAULT_MAX_FILES = 10_000;
const DEFAULT_MAX_TOTAL_BYTES = 1 << 30; // 1 GiB

/** ZIP local-file-header magic: "PK\x03\x04". */
export function isZipArchive(bytes: Uint8Array): boolean {
  return (
    bytes.length >= 4 &&
    bytes[0] === 0x50 &&
    bytes[1] === 0x4b &&
    bytes[2] === 0x03 &&
    bytes[3] === 0x04
  );
}

export interface ArchiveContents {
  /** UTF-8 JSON text of index.json. */
  indexJson: string;
  /** File-credential payloads keyed by file id (the documents/ entry name). */
  files: Map<string, Uint8Array>;
}

export function readArchive(bytes: Uint8Array, limits: ArchiveLimits = {}): ArchiveContents {
  const maxFiles = limits.maxFiles ?? DEFAULT_MAX_FILES;
  const maxTotalBytes = limits.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;

  const overLimit = (detail: string): CxfParseError =>
    new CxfParseError(
      "CXF1006",
      `Archive exceeds limits (${detail}); raise ArchiveLimits if this export is legitimate.`,
    );

  // First line of defense: reject on the sizes entries *declare*, before
  // decompressing them.
  let count = 0;
  let declared = 0;
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes, {
      filter: (file) => {
        count += 1;
        declared += file.originalSize;
        if (count > maxFiles) throw overLimit(`more than ${maxFiles} entries`);
        if (declared > maxTotalBytes) {
          throw overLimit(`declared decompressed size over ${maxTotalBytes} bytes`);
        }
        return true;
      },
    });
  } catch (cause) {
    if (cause instanceof CxfParseError) throw cause;
    throw new CxfParseError("CXF1003", "Input looks like a ZIP archive but could not be read.", {
      cause,
    });
  }

  // Second line: declared sizes can lie, so re-check what actually came out.
  let actual = 0;
  for (const data of Object.values(entries)) {
    actual += data.byteLength;
    if (actual > maxTotalBytes) {
      throw overLimit(`decompressed content over ${maxTotalBytes} bytes`);
    }
  }

  const index = entries[ARCHIVE_INDEX];
  if (index === undefined) {
    throw new CxfParseError(
      "CXF1004",
      `Archive has no "${ARCHIVE_INDEX}" entry; not a CXF export archive.`,
    );
  }

  const files = new Map<string, Uint8Array>();
  for (const [path, data] of Object.entries(entries)) {
    if (!path.startsWith(ARCHIVE_DOCUMENTS_PREFIX) || path.endsWith("/")) continue;
    const id = path.slice(ARCHIVE_DOCUMENTS_PREFIX.length);
    if (!FILE_ID_RE.test(id)) {
      throw new CxfParseError(
        "CXF1008",
        `Archive entry "${path}" is not a valid file id: names under ${ARCHIVE_DOCUMENTS_PREFIX} must be base64url (no path separators).`,
      );
    }
    files.set(id, data);
  }

  return { indexJson: decodeUtf8Strict(index, `Archive entry "${ARCHIVE_INDEX}"`), files };
}

export function writeArchive(indexJson: string, files: ReadonlyMap<string, Uint8Array>): Uint8Array {
  const entries: Record<string, Uint8Array> = {
    [ARCHIVE_INDEX]: new TextEncoder().encode(indexJson),
  };
  for (const [id, data] of files) {
    if (!FILE_ID_RE.test(id)) {
      throw new Error(
        `File id "${id}" is not base64url; refusing to write an unsafe archive entry name.`,
      );
    }
    entries[ARCHIVE_DOCUMENTS_PREFIX + id] = data;
  }
  return zipSync(entries);
}
