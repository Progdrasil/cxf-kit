# cxf-kit — Plan

A toolkit for the FIDO **Credential Exchange Format (CXF) v1.0**, built against the
**Proposed Standard of 2025-08-14** (`https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html`).
The spec's CDDL index is vendored verbatim at `spec/cxf-v1.0-ps-20250814.cddl` as the
ground truth for the data models and validator.

## Language & stack

**TypeScript** (strict), Node ≥ 18. *The request didn't name a language — this is my
pick, chosen because CXF is a pure JSON format: TS types can mirror the wire format
1:1, which makes lossless round-tripping natural. Veto at the type-review checkpoint
if you want something else; nothing downstream exists yet.*

- Runtime deps: `fflate` only (ZIP read/write for archives). Everything else hand-rolled —
  in particular validation, so errors can be exactly the structured shape we want.
- Dev deps: `typescript`, `vitest`, `tsx`.
- CLI: plain Node with `util.parseArgs` (no commander/yargs).

## Deliverables

1. **Data models** (`src/types.ts`) — Header, Version, Account, Collection, LinkedItem,
   Item, CredentialScope, all 17 credential types, EditableField, Extension (+ the
   registered `shared` extension), and every enum. Types mirror the JSON wire format
   exactly; open enums use the `KnownValue | (string & {})` idiom since the spec makes
   every enum extensible (`Enum / tstr`) and requires importers to tolerate unknown values.
2. **Parser** (`src/parse.ts`, `src/archive.ts`) — reads a bare CXF JSON document *or* a
   ZIP export archive (layout below). Structure-checks as it goes and returns
   `{ document, diagnostics }`; it does not throw on recoverable problems.
3. **Serializer** (`src/serialize.ts`) — spec-compliant JSON output: canonical key order,
   optional-and-empty arrays omitted (per CDDL `.default []`), unknown/extension members
   preserved byte-for-value. Also writes the ZIP archive form.
4. **Validator** (`src/validate.ts`) — structured errors:
   `{ severity: "error" | "warning", code: "CXF####", path: "accounts[0].items[2].credentials[0].secret", message }`,
   with human-readable messages. Covers: required members, member types, enum membership
   (unknown enum → warning, per the spec's ignore rules), b64url validity + decoded-length
   caps on ids, LinkedItem/ItemReference referential integrity, FieldType/value coherence
   (date, year-month, boolean, country-code shapes), TOTP constraints, passkey key format
   (PKCS#8 DER plausibility), Shared-extension rules (e.g. empty `permissions` ⇒ ignored).
5. **CLI** (`src/cli.ts`) — `cxf validate <file>` (exit 1 on errors, pretty + `--json`
   output) and `cxf inspect <file>` (summary tree: accounts, collections, items,
   credential-type histogram; `--redact` on by default for concealed values).

## Archive layout (kit-defined — spec is silent)

The spec defines only the JSON payload, **no on-disk packaging** (transfer is CXP's job).
Logged in SPEC_NOTES.md. This kit's archive convention:

```
export.cxf (ZIP)
├── index.json          # the CXF Header document
└── documents/<fileId>  # one entry per File credential, named by its b64url id
```

Bare `.json` files (no File credential payloads) are accepted everywhere too; the parser
sniffs ZIP magic (`PK\x03\x04`) vs JSON.

## Round-trip guarantee (mandatory tests)

`parse(serialize(parse(x)))` deep-equals `parse(x)` for every fixture, including ones
with unknown credential types, unknown enum values, custom extensions, and extra
members — i.e. the parser never drops data it doesn't understand. Byte-identity is NOT
the guarantee (key order/whitespace may differ on first normalization); value-identity is.
Additionally `serialize(parse(y)) === y` for already-canonical fixtures.

## Work order & checkpoints

1. ✅ PLAN.md + SPEC_NOTES.md (this commit)
2. Data models (`src/types.ts`) → **STOP: show type definitions for review**
3. Parser + archive reader, with fixtures
4. Serializer + round-trip tests
5. Validator
6. CLI
7. Polish: README, `npm pack` sanity check

Commit after each working chunk. Any spec ambiguity → flag to Yusuf, log resolution in
SPEC_NOTES.md.
