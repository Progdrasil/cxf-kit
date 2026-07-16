import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Diagnostic } from "../src/diagnostics.js";
import { parseCxf } from "../src/parse.js";
import { serializeCxfArchive } from "../src/serialize.js";
import { DIAGNOSTIC_CODES, validateCxf, validateDocument } from "../src/validate.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures");

function load(...parts: string[]): unknown {
  return JSON.parse(readFileSync(join(FIXTURES, ...parts), "utf-8"));
}

function errors(diags: Diagnostic[]): Diagnostic[] {
  return diags.filter((d) => d.severity === "error");
}

function codes(diags: Diagnostic[]): string[] {
  return diags.map((d) => d.code);
}

/** Deep-clone + apply a mutation; keeps fixture objects pristine. */
function mutate<T>(value: T, fn: (copy: T) => void): T {
  const copy = structuredClone(value) as T;
  fn(copy);
  return copy;
}

describe("well-formedness of all diagnostics", () => {
  it("every diagnostic carries a registered code and a non-empty path", () => {
    const hostile = load("synthetic", "kitchen-sink.json") as never;
    const mutated = mutate<Record<string, unknown>>(hostile, (d) => {
      delete d["exporterRpId"];
      (d["accounts"] as unknown[]).push(42, { id: "!!!bad" });
    });
    const diags = [...validateCxf(mutated), ...validateCxf(null), ...validateCxf([])];
    expect(diags.length).toBeGreaterThan(0);
    for (const d of diags) {
      expect(d.code, JSON.stringify(d)).toMatch(/^CXF2\d{3}$/);
      expect(d.code in DIAGNOSTIC_CODES).toBe(true);
      expect(d.path.length).toBeGreaterThan(0);
      expect(d.message.length).toBeGreaterThan(0);
    }
  });
});

describe("interop fixtures produce no false-positive errors", () => {
  it("spec Appendix A: zero errors; its known slips surface as warnings", () => {
    const diags = validateCxf(load("spec", "appendix-a.json"));
    expect(errors(diags)).toEqual([]);
    // Off-CDDL hmacSecret member (SPEC_NOTES #11).
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2003", path: expect.stringContaining("fido2Extensions.hmacSecret") }),
    );
    // Present-but-empty EditableField extensions array (SPEC_NOTES #11).
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2009", path: expect.stringContaining("expiryDate.extensions") }),
    );
    // "WPA2" is not a WIFINetworkSecurityType; bare "CA" is not ISO 3166-2.
    expect(codes(diags)).toContain("CXF2004");
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2008", severity: "warning", path: expect.stringContaining("territory") }),
    );
  });

  it("handles both fido2 hmac shapes: CDDL hmacCredentials silently, example hmacSecret as a warning", () => {
    // Groundwork for the upstream FIDO report (PLAN.md post-v0.1 #1).
    const kitchen = validateCxf(load("synthetic", "kitchen-sink.json"));
    expect(kitchen.filter((d) => d.path.includes("hmacCredentials"))).toEqual([]);
    const appendix = validateCxf(load("spec", "appendix-a.json"));
    const hmac = appendix.filter((d) => d.path.includes("hmacSecret"));
    expect(hmac).toHaveLength(1);
    expect(hmac[0]?.severity).toBe("warning");
  });

  it("kitchen-sink: zero errors; unknown enum values and permissions warn", () => {
    const diags = validateCxf(load("synthetic", "kitchen-sink.json"));
    expect(errors(diags)).toEqual([]);
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2004", path: expect.stringContaining("algorithm") }), // sha3-512
    );
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2004", path: expect.stringContaining("fields[0].fieldType") }), // totp-secret
    );
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2013", path: expect.stringContaining("permissions[2]") }), // quantum-veto
    );
    // Custom RP_ID/NAME extensions are fine — no CXF2012.
    expect(codes(diags)).not.toContain("CXF2012");
  });

  it("Bitwarden fragments validate cleanly once wrapped", () => {
    const fragment = load("interop", "bitwarden", "custom-fields.deserialize.json") as object;
    const header = {
      version: { major: 1, minor: 0 },
      exporterRpId: "test.example",
      exporterDisplayName: "test",
      timestamp: 1,
      accounts: [
        {
          id: "dGVzdA",
          username: "t",
          email: "t@example.com",
          collections: [],
          items: [
            {
              id: "aXRlbQ",
              title: "wrapped",
              credentials: [
                { type: "custom-fields", ...fragment },
                JSON.parse(readFileSync(join(FIXTURES, "interop", "bitwarden", "unknown-credential.json"), "utf-8")),
              ],
            },
          ],
        },
      ],
    };
    const diags = validateCxf(header);
    expect(errors(diags)).toEqual([]);
    expect(diags).toContainEqual(
      expect.objectContaining({ code: "CXF2004", path: expect.stringContaining("credentials[1].type") }),
    );
  });
});

describe("mutations are caught with the right code, path, and severity", () => {
  const base = load("synthetic", "kitchen-sink.json") as never as Record<string, never>;
  type Doc = {
    version: { major: number };
    timestamp: number;
    accounts: Array<{
      id: string;
      items: Array<{ id: string; credentials: Array<Record<string, unknown>>; extensions?: unknown[] }>;
      collections: Array<{ items: Array<{ item: string }> }>;
    }>;
  };

  const cases: Array<{
    name: string;
    change: (d: Doc) => void;
    code: string;
    severity: "error" | "warning";
    pathIncludes: string;
  }> = [
    {
      name: "missing TOTP secret",
      change: (d) => delete (d.accounts[0]!.items[0]!.credentials[1] as { secret?: string }).secret,
      code: "CXF2001", severity: "error", pathIncludes: "credentials[1]",
    },
    {
      name: "missing TOTP period falls back to importer default",
      change: (d) => delete (d.accounts[0]!.items[0]!.credentials[1] as { period?: number }).period,
      code: "CXF2014", severity: "warning", pathIncludes: "period",
    },
    {
      name: "malformed date value",
      change: (d) => {
        (d.accounts[0]!.items[0]!.credentials[3] as { validFrom: { value: string } }).validFrom.value = "01/01/2026";
      },
      code: "CXF2008", severity: "error", pathIncludes: "validFrom.value",
    },
    {
      name: "non-base64url id",
      change: (d) => { d.accounts[0]!.items[0]!.id = "not+valid/id="; },
      code: "CXF2005", severity: "error", pathIncludes: "items[0].id",
    },
    {
      name: "id over 64 decoded bytes",
      change: (d) => { d.accounts[0]!.items[0]!.id = "A".repeat(120); },
      code: "CXF2006", severity: "error", pathIncludes: "items[0].id",
    },
    {
      name: "dangling collection reference",
      change: (d) => { d.accounts[0]!.collections[0]!.items[0]!.item = "bm9wZQ"; },
      code: "CXF2010", severity: "error", pathIncludes: "collections[0].items[0].item",
    },
    {
      name: "duplicate item ids",
      change: (d) => { d.accounts[0]!.items[1]!.id = d.accounts[0]!.items[0]!.id; },
      code: "CXF2011", severity: "error", pathIncludes: "items[1].id",
    },
    {
      name: "present-but-empty optional extensions",
      change: (d) => { d.accounts[0]!.items[0]!.extensions = []; },
      code: "CXF2009", severity: "warning", pathIncludes: "items[0].extensions",
    },
    {
      name: "negative timestamp",
      change: (d) => { d.timestamp = -5; },
      code: "CXF2007", severity: "error", pathIncludes: "timestamp",
    },
    {
      name: "unsupported major version",
      change: (d) => { d.version.major = 2; },
      code: "CXF2015", severity: "warning", pathIncludes: "version.major",
    },
    {
      name: "wrong member type",
      change: (d) => { (d.accounts[0] as unknown as { username: unknown }).username = 42; },
      code: "CXF2002", severity: "error", pathIncludes: "username",
    },
    {
      name: "extension without RP_ID/NAME form",
      change: (d) => { d.accounts[0]!.items[0]!.extensions = [{ name: "VaultColor" }]; },
      code: "CXF2012", severity: "warning", pathIncludes: "extensions[0].name",
    },
  ];

  for (const c of cases) {
    it(c.name, () => {
      const diags = validateCxf(mutate(base as never as Doc, c.change));
      expect(diags).toContainEqual(
        expect.objectContaining({
          code: c.code,
          severity: c.severity,
          path: expect.stringContaining(c.pathIncludes),
        }),
      );
    });
  }
});

describe("library and CLI surfaces agree", () => {
  it("validateCxf accepts the CxfDocument wrapper and matches validateDocument", () => {
    const text = readFileSync(join(FIXTURES, "spec", "appendix-a.json"), "utf-8");
    const doc = parseCxf(text);
    // The consumer footgun: passing parseCxf's result instead of .header.
    expect(validateCxf(doc)).toEqual(validateDocument(doc));
    expect(validateCxf(doc)).toEqual(validateCxf(doc.header));
    expect(validateCxf(doc)).toHaveLength(5);
  });

  it("wrapper detection does not swallow a genuine document that merely has those member names", () => {
    // files is a JSON array here, not a Map — must be validated as a Header, not unwrapped.
    const impostor = { header: {}, files: [], source: "json" };
    const diags = validateCxf(impostor);
    expect(diags.some((d) => d.code === "CXF2001")).toBe(true);
    expect(diags.some((d) => d.path === "$.header")).toBe(true);
  });
});

describe("archive consistency", () => {
  const text = readFileSync(join(FIXTURES, "synthetic", "kitchen-sink.json"), "utf-8");
  const goodPayload = new TextEncoder().encode("recovery: 1111-2222-3333\n");

  it("clean archive: no file diagnostics", () => {
    const zip = serializeCxfArchive({ header: parseCxf(text).header, files: new Map([["ZG9jMQ", goodPayload]]) });
    const diags = validateDocument(parseCxf(zip));
    expect(diags.filter((d) => d.code === "CXF2016" || d.code === "CXF2017")).toEqual([]);
  });

  it("tampered payload: hash and size errors", () => {
    const zip = serializeCxfArchive({
      header: parseCxf(text).header,
      files: new Map([["ZG9jMQ", new TextEncoder().encode("tampered!")]]),
    });
    const diags = validateDocument(parseCxf(zip));
    expect(codes(errors(diags))).toContain("CXF2016");
  });

  it("missing payload: warning, not error", () => {
    const zip = serializeCxfArchive({ header: parseCxf(text).header, files: new Map() });
    const diags = validateDocument(parseCxf(zip));
    expect(diags).toContainEqual(expect.objectContaining({ code: "CXF2017", severity: "warning" }));
    expect(errors(diags)).toEqual([]);
  });

  it("bare JSON documents skip file checks entirely", () => {
    const diags = validateDocument(parseCxf(text));
    expect(diags.filter((d) => d.code === "CXF2016" || d.code === "CXF2017")).toEqual([]);
  });
});
