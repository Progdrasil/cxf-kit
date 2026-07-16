import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCxf } from "../src/parse.js";
import { serializeCxf, serializeCxfArchive } from "../src/serialize.js";

const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures");

const DOCUMENT_FIXTURES = [
  ["spec", "appendix-a.json"],
  ["synthetic", "kitchen-sink.json"],
] as const;

describe("round-trip guarantee", () => {
  for (const parts of DOCUMENT_FIXTURES) {
    const name = parts.join("/");
    const text = readFileSync(join(FIXTURES, ...parts), "utf-8");

    it(`${name}: parse -> serialize -> parse is value-identical`, () => {
      const first = parseCxf(text).header;
      const second = parseCxf(serializeCxf(first)).header;
      expect(second).toEqual(first);
    });

    it(`${name}: serialization is idempotent byte-for-byte`, () => {
      const once = serializeCxf(parseCxf(text).header);
      const twice = serializeCxf(parseCxf(once).header);
      expect(twice).toBe(once);
    });
  }

  it("preserves unknown credentials, extensions, and off-CDDL members through a round-trip", () => {
    const text = readFileSync(join(FIXTURES, "synthetic", "kitchen-sink.json"), "utf-8");
    const round = parseCxf(serializeCxf(parseCxf(text).header)).header;
    const asJson = JSON.stringify(round);
    // Unknown credential body, custom extension bodies, unknown enum values.
    expect(asJson).toContain('"memberNumber":"1234567890"');
    expect(asJson).toContain('"cxf-kit.example/VaultMeta"');
    expect(asJson).toContain('"sha3-512"');
    expect(asJson).toContain('"quantum-veto"');

    const appendix = readFileSync(join(FIXTURES, "spec", "appendix-a.json"), "utf-8");
    const roundA = parseCxf(serializeCxf(parseCxf(appendix).header)).header;
    expect(JSON.stringify(roundA)).toContain('"hmacSecret"');
  });

  it("orders members canonically (CDDL order, unknown members last)", () => {
    const header = parseCxf(
      JSON.stringify({
        accounts: [],
        timestamp: 1,
        exporterDisplayName: "d",
        vendorNote: "not in the spec",
        exporterRpId: "r",
        version: { minor: 0, major: 1 },
      }),
    ).header;
    const out = JSON.parse(serializeCxf(header)) as Record<string, unknown>;
    expect(Object.keys(out)).toEqual([
      "version",
      "exporterRpId",
      "exporterDisplayName",
      "timestamp",
      "accounts",
      "vendorNote",
    ]);
    expect(Object.keys(out["version"] as object)).toEqual(["major", "minor"]);
  });

  it("normalize: true omits optional arrays when empty, per the exporter rules", () => {
    const text = readFileSync(join(FIXTURES, "synthetic", "kitchen-sink.json"), "utf-8");
    const header = parseCxf(text).header;
    const item = header.accounts[0]!.items[1]!; // passkey item: no tags/extensions
    item.tags = [];
    item.extensions = [];
    const out = parseCxf(serializeCxf(header, { normalize: true })).header;
    const outItem = out.accounts[0]!.items[1]!;
    expect("tags" in outItem).toBe(false);
    expect("extensions" in outItem).toBe(false);
    // Required arrays stay even when empty.
    expect(out.accounts[1]!.collections).toEqual([]);
    // Default mode preserves them: value-identity beats normalization.
    const preserved = parseCxf(serializeCxf(header)).header;
    expect(preserved.accounts[0]!.items[1]!.tags).toEqual([]);
  });

  it("preserves Appendix A's own nonconforming empty extensions array by default", () => {
    const text = readFileSync(join(FIXTURES, "spec", "appendix-a.json"), "utf-8");
    const round = parseCxf(serializeCxf(parseCxf(text).header)).header;
    const dl = round.accounts[0]!.items[7]!.credentials[0]!;
    expect((dl as Record<string, Record<string, unknown>>)["expiryDate"]!["extensions"]).toEqual(
      [],
    );
  });

  it("round-trips the ZIP archive form with file payloads intact", () => {
    const text = readFileSync(join(FIXTURES, "synthetic", "kitchen-sink.json"), "utf-8");
    const payload = new TextEncoder().encode("recovery: 1111-2222-3333\n");
    const doc = parseCxf(text);
    const zip = serializeCxfArchive({ header: doc.header, files: new Map([["ZG9jMQ", payload]]) });
    const back = parseCxf(zip);
    expect(back.source).toBe("archive");
    expect(back.header).toEqual(doc.header);
    expect(back.files.get("ZG9jMQ")).toEqual(payload);
    // And the archive's index round-trips byte-identically too.
    const zip2 = serializeCxfArchive({ header: back.header, files: back.files });
    expect(parseCxf(zip2).header).toEqual(doc.header);
  });
});
