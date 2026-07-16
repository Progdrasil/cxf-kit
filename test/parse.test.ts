import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { zipSync } from "fflate";
import { describe, expect, it } from "vitest";
import { writeArchive } from "../src/archive.js";
import { CxfParseError } from "../src/diagnostics.js";
import {
  credentialOfType,
  isKnownCredential,
  isSharedExtension,
  isUnknownCredential,
} from "../src/guards.js";
import { parseCxf } from "../src/parse.js";
import type { Credential, Header, Item } from "../src/types.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures");

function fixture(...parts: string[]): string {
  return readFileSync(join(FIXTURES, ...parts), "utf-8");
}

function allCredentials(header: Header): Credential[] {
  return header.accounts.flatMap((a) => a.items.flatMap((i) => i.credentials));
}

/** Wraps loose credential fragments into a minimal Header for parser input. */
function wrap(credentials: Credential[]): string {
  const header: Header = {
    version: { major: 1, minor: 0 },
    exporterRpId: "test.example",
    exporterDisplayName: "test",
    timestamp: 1752624000,
    accounts: [
      {
        id: "dGVzdA",
        username: "t",
        email: "t@example.com",
        collections: [],
        items: [{ id: "aXRlbQ", title: "wrapped", credentials }],
      },
    ],
  };
  return JSON.stringify(header);
}

describe("spec Appendix A fixture", () => {
  const { header, files, source } = parseCxf(fixture("spec", "appendix-a.json"));

  it("parses the full example payload", () => {
    expect(source).toBe("json");
    expect(files.size).toBe(0);
    expect(header.version).toEqual({ major: 1, minor: 0 });
    expect(header.exporterRpId).toBe("exporter.example.com");
    expect(header.accounts).toHaveLength(1);
    expect(header.accounts[0]?.items).toHaveLength(14);
  });

  it("covers 15 known credential types, all recognized by the guards", () => {
    const creds = allCredentials(header);
    expect(new Set(creds.map((c) => c.type)).size).toBe(15);
    expect(creds.every((c) => isKnownCredential(c))).toBe(true);
  });

  it("preserves the example's off-CDDL fido2Extensions.hmacSecret member", () => {
    const passkey = allCredentials(header).find((c) => credentialOfType(c, "passkey"));
    expect(passkey).toBeDefined();
    // Appendix A deviates from the CDDL here (SPEC_NOTES); the parser must not drop it.
    expect((passkey?.fido2Extensions as Record<string, unknown>)["hmacSecret"]).toEqual({
      algorithm: "HS256",
      secret: "c2VjcmV0X2tleV9kYXRh",
    });
  });
});

describe("kitchen-sink fixture", () => {
  const { header } = parseCxf(fixture("synthetic", "kitchen-sink.json"));

  it("covers all 17 credential types plus one unknown", () => {
    const creds = allCredentials(header);
    const known = creds.filter(isKnownCredential);
    const unknown = creds.filter(isUnknownCredential);
    expect(new Set(known.map((c) => c.type)).size).toBe(17);
    expect(unknown).toHaveLength(1);
  });

  it("preserves unknown credential content verbatim", () => {
    const unknown = allCredentials(header).find(isUnknownCredential);
    expect(unknown?.type).toBe("cxf-kit.example/loyalty-card");
    expect(unknown?.["memberNumber"]).toBe("1234567890");
    expect(unknown?.["tier"]).toEqual({ level: 3, name: "gold" });
  });

  it("keeps open-enum values that are not in the known tables", () => {
    const totp = allCredentials(header).find((c) => credentialOfType(c, "totp"));
    expect(totp?.algorithm).toBe("sha3-512");
    const custom = allCredentials(header).find((c) => credentialOfType(c, "custom-fields"));
    expect(custom?.fields[0]?.fieldType).toBe("totp-secret");
  });

  it("exposes the shared extension through its guard, with unknown permissions kept", () => {
    const coll = header.accounts[0]?.collections[0];
    const shared = coll?.extensions?.find(isSharedExtension);
    expect(shared?.accessors[0]?.permissions).toEqual(["read", "readSecret", "quantum-veto"]);
    const custom = header.accounts[0]?.extensions?.find(
      (e) => e.name === "cxf-kit.example/VaultMeta",
    );
    expect(custom?.["vaultName"]).toBe("personal");
  });

  it("links the item-reference across accounts", () => {
    const ref = allCredentials(header).find((c) => credentialOfType(c, "item-reference"));
    expect(ref?.reference).toEqual({ item: "aXRlbS1zaGFyZWQ", account: "YWNjb3VudC1i" });
    const target = header.accounts
      .find((a) => a.id === "YWNjb3VudC1i")
      ?.items.find((i) => i.id === "aXRlbS1zaGFyZWQ");
    expect(target?.title).toBe("Shared server");
  });
});

describe("Bitwarden interop fragments", () => {
  it("parses both custom-fields fragments once given their enum type tag", () => {
    for (const name of ["custom-fields.serialize.json", "custom-fields.deserialize.json"]) {
      const fragment = JSON.parse(fixture("interop", "bitwarden", name)) as Record<
        string,
        unknown
      >;
      // Bitwarden's tests serialize the inner struct; the "type" tag comes
      // from their Credential enum wrapper (see fixtures README).
      const { header } = parseCxf(wrap([{ type: "custom-fields", ...fragment } as Credential]));
      const cred = allCredentials(header)[0];
      expect(cred && credentialOfType(cred, "custom-fields")).toBe(true);
      if (cred && credentialOfType(cred, "custom-fields")) {
        expect(cred.fields.length).toBeGreaterThanOrEqual(2);
        expect(cred.fields.every((f) => typeof f.value === "string")).toBe(true);
      }
    }
  });

  it("treats Bitwarden's future-credential fragment as unknown, like their Rust enum does", () => {
    const fragment = JSON.parse(fixture("interop", "bitwarden", "unknown-credential.json"));
    const { header } = parseCxf(wrap([fragment]));
    const cred = allCredentials(header)[0];
    expect(cred && isUnknownCredential(cred)).toBe(true);
    expect(cred?.type).toBe("future-credential");
  });
});

describe("export archives", () => {
  const indexJson = fixture("synthetic", "kitchen-sink.json");
  const payload = new TextEncoder().encode("recovery: 1111-2222-3333\n");

  it("round-trips through the kit's ZIP layout", () => {
    const zip = writeArchive(indexJson, new Map([["ZG9jMQ", payload]]));
    const doc = parseCxf(zip);
    expect(doc.source).toBe("archive");
    expect(doc.header.exporterRpId).toBe("cxf-kit.example");
    expect(doc.files.get("ZG9jMQ")).toEqual(payload);
  });

  it("stores bytes whose hash and size match the file credential", () => {
    const zip = writeArchive(indexJson, new Map([["ZG9jMQ", payload]]));
    const doc = parseCxf(zip);
    const file = allCredentials(doc.header).find((c) => credentialOfType(c, "file"));
    const bytes = doc.files.get(file!.id)!;
    expect(bytes.byteLength).toBe(file!.decryptedSize);
    const hash = createHash("sha256").update(bytes).digest("base64url");
    expect(hash).toBe(file!.integrityHash);
  });

  it("accepts bare JSON given as bytes", () => {
    const doc = parseCxf(new TextEncoder().encode(indexJson));
    expect(doc.source).toBe("json");
    expect(doc.header.accounts).toHaveLength(2);
  });
});

describe("unusable input", () => {
  function codeOf(fn: () => unknown): string {
    try {
      fn();
    } catch (e) {
      if (e instanceof CxfParseError) return e.code;
      throw e;
    }
    throw new Error("expected CxfParseError");
  }

  it("rejects malformed JSON, wrong roots, and index-less ZIPs with stable codes", () => {
    expect(codeOf(() => parseCxf("{ not json"))).toBe("CXF1001");
    expect(codeOf(() => parseCxf("[1, 2]"))).toBe("CXF1002");
    expect(codeOf(() => parseCxf('{"hello": "world"}'))).toBe("CXF1005");
    const zipWithoutIndex = zipSync({ "readme.txt": new TextEncoder().encode("hi") });
    expect(codeOf(() => parseCxf(zipWithoutIndex))).toBe("CXF1004");
  });

  it("rejects invalid UTF-8 instead of silently substituting U+FFFD", () => {
    // 0xFF can never appear in UTF-8.
    const badJson = new Uint8Array([0x7b, 0x22, 0xff, 0x22, 0x7d]);
    expect(codeOf(() => parseCxf(badJson))).toBe("CXF1007");
    const badIndex = zipSync({ "index.json": new Uint8Array([0xff, 0xfe, 0x00]) });
    expect(codeOf(() => parseCxf(badIndex))).toBe("CXF1007");
  });

  it("enforces archive entry-count and decompressed-size limits", () => {
    const index = new TextEncoder().encode(wrap([]));
    const many = zipSync({
      "index.json": index,
      "documents/YQ": new Uint8Array(1),
      "documents/Yg": new Uint8Array(1),
      "documents/Yw": new Uint8Array(1),
    });
    expect(codeOf(() => parseCxf(many, { archiveLimits: { maxFiles: 2 } }))).toBe("CXF1006");
    const big = zipSync({ "index.json": index, "documents/YQ": new Uint8Array(4096) });
    expect(codeOf(() => parseCxf(big, { archiveLimits: { maxTotalBytes: 1024 } }))).toBe(
      "CXF1006",
    );
    // Defaults let a normal export through.
    expect(parseCxf(many).files.size).toBe(3);
  });

  it("rejects documents/ entry names outside the b64url alphabet (path traversal)", () => {
    const index = new TextEncoder().encode(wrap([]));
    for (const name of ["documents/../../evil", "documents/a/b", "documents/na+me"]) {
      const zip = zipSync({ "index.json": index, [name]: new Uint8Array(1) });
      expect(codeOf(() => parseCxf(zip)), name).toBe("CXF1008");
    }
  });

  it("refuses to write archive entries with unsafe file ids", () => {
    expect(() => writeArchive("{}", new Map([["../evil", new Uint8Array(1)]]))).toThrow(
      /unsafe archive entry name/,
    );
  });
});
