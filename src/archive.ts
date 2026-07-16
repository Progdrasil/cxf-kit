/**
 * cxf-kit's export-archive convention. The CXF spec defines only the JSON
 * payload and no on-disk packaging (SPEC_NOTES #1), so this layout is
 * kit-defined:
 *
 *   export.cxf (ZIP)
 *   ├── index.json          the CXF Header document
 *   └── documents/<fileId>  bytes for each File credential, named by its id
 */

import { unzipSync, zipSync } from "fflate";
import { CxfParseError } from "./diagnostics.js";

export const ARCHIVE_INDEX = "index.json";
export const ARCHIVE_DOCUMENTS_PREFIX = "documents/";

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

export function readArchive(bytes: Uint8Array): ArchiveContents {
  let entries: Record<string, Uint8Array>;
  try {
    entries = unzipSync(bytes);
  } catch (cause) {
    throw new CxfParseError("CXF1003", "Input looks like a ZIP archive but could not be read.", {
      cause,
    });
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
    if (path.startsWith(ARCHIVE_DOCUMENTS_PREFIX) && !path.endsWith("/")) {
      files.set(path.slice(ARCHIVE_DOCUMENTS_PREFIX.length), data);
    }
  }

  return { indexJson: new TextDecoder("utf-8", { fatal: false }).decode(index), files };
}

export function writeArchive(indexJson: string, files: ReadonlyMap<string, Uint8Array>): Uint8Array {
  const entries: Record<string, Uint8Array> = {
    [ARCHIVE_INDEX]: new TextEncoder().encode(indexJson),
  };
  for (const [id, data] of files) {
    entries[ARCHIVE_DOCUMENTS_PREFIX + id] = data;
  }
  return zipSync(entries);
}
