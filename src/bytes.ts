import { CxfParseError } from "./diagnostics.js";

/**
 * Strict UTF-8 decode. In a credential format, silently substituting U+FFFD
 * for invalid bytes can corrupt a secret without anyone noticing — failing
 * loudly is safer, so invalid UTF-8 is a parse error (CXF1007).
 */
export function decodeUtf8Strict(bytes: Uint8Array, what: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (cause) {
    throw new CxfParseError("CXF1007", `${what} is not valid UTF-8.`, { cause });
  }
}
