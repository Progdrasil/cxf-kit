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

/** Thrown only when input is unusable (not JSON, not a CXF shape, broken ZIP). */
export class CxfParseError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(`${code}: ${message}`, options);
    this.name = "CxfParseError";
    this.code = code;
  }
}
