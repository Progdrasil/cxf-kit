/**
 * Structured problem reports shared by the parser and validator.
 *
 * Code ranges: CXF1xxx parser/archive, CXF2xxx validator.
 */

export type Severity = "error" | "warning";

export interface Diagnostic {
  severity: Severity;
  /** Stable machine identifier, e.g. "CXF1001". */
  code: string;
  /** JSONPath-ish location, e.g. "accounts[0].items[2].credentials[0].secret". */
  path: string;
  /** Human-readable, self-contained explanation. */
  message: string;
}

/** Every code CxfParseError can carry, with its meaning. */
export const PARSE_ERROR_CODES = {
  CXF1001: "input is not valid JSON",
  CXF1002: "document root is not a JSON object",
  CXF1003: "ZIP archive could not be read",
  CXF1004: "archive has no index.json entry",
  CXF1005: "root object has no accounts array",
  CXF1006: "archive exceeds the file-count or decompressed-size limit",
  CXF1007: "input is not valid UTF-8",
  CXF1008: "unsafe archive entry name under documents/",
} as const;

export type ParseErrorCode = keyof typeof PARSE_ERROR_CODES;

/** Thrown only when input is unusable (not JSON, not a CXF shape, broken ZIP). */
export class CxfParseError extends Error {
  readonly code: ParseErrorCode;

  constructor(code: ParseErrorCode, message: string, options?: ErrorOptions) {
    super(`${code}: ${message}`, options);
    this.name = "CxfParseError";
    this.code = code;
  }
}
