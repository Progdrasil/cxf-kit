# cxf-kit

TypeScript data models, parser, serializer, validator, and CLI for the
**FIDO Credential Exchange Format (CXF) v1.0** — built against the
[Proposed Standard of 2025-08-14](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html),
whose CDDL index is vendored verbatim at
[`spec/cxf-v1.0-ps-20250814.cddl`](spec/cxf-v1.0-ps-20250814.cddl) as the single
source of truth. (The March 2025 Review Draft that Bitwarden's Rust library targets
is wire-identical — see [SPEC_NOTES §10](SPEC_NOTES.md).)

Node ≥ 18. One runtime dependency (`fflate`, for the ZIP archive form).

```
npm install   # then:
npm test      # 52 tests: guards, parser, round-trip, validator
npm run cxf -- validate <file>
```

## Library

```ts
import { parseCxf, validateDocument, serializeCxf, credentialOfType } from "cxf-kit";

const doc = parseCxf(readFileSync("export.cxf"));   // JSON text, JSON bytes, or ZIP bytes
const problems = validateDocument(doc);             // [{ severity, code, path, message }]

for (const item of doc.header.accounts[0].items) {
  for (const cred of item.credentials) {
    if (credentialOfType(cred, "passkey")) console.log(cred.rpId); // fully narrowed
  }
}

writeFileSync("export.json", serializeCxf(doc.header));
```

Design decisions that matter:

- **Types mirror the wire format 1:1** (`src/types.ts`), in CDDL member order, all
  17 credential types. Every enum position is open (`Known / tstr` in the CDDL), so
  enums are typed `Known | (string & {})` — autocomplete without rejecting the
  unknown values importers must tolerate.
- **Unknown content is first-class.** Credentials with unknown `type` and all
  extension bodies are preserved verbatim, never dropped. Runtime guards
  (`isKnownCredential`, `credentialOfType`, `isSharedExtension`) make the
  `Credential` union discriminable despite that openness.
- **The parser is lossless and minimal; the validator owns every rule.**
  `parseCxf` decodes and gates only on unusable input (bad JSON/UTF-8/ZIP —
  `CxfParseError` with stable `CXF1xxx` codes). Conformance lives entirely in
  `validateCxf`/`validateDocument`, which take raw `unknown` and return structured
  diagnostics with stable `CXF2xxx` codes (see `DIAGNOSTIC_CODES`). Severity
  policy: CDDL violations are errors; anything the spec tells importers to
  tolerate is a warning.

## Round-trip guarantee

Stated precisely:

- `parse(serialize(parse(x)))` is **value-identical** to `parse(x)` for **any**
  input — including unknown credential types, unknown enum values, custom
  extensions, off-spec members, and even nonconforming documents. Serialization
  reorders members canonically (CDDL order, unknown members last) but never adds
  or removes a value.
- `serialize(parse(serialize(parse(x))))` is **byte-identical** to
  `serialize(parse(x))` (idempotence).
- `serializeCxf(header, { normalize: true })` additionally applies the spec's
  exporter rules (omit optional-and-empty arrays). This is opt-in because the
  spec's own Appendix A would not survive it losslessly — it carries a
  present-but-empty `extensions` array (see finding 4 below). The validator
  flags documents that need normalization (`CXF2009`).

`test/roundtrip.test.ts` enforces all three properties over the spec's Appendix A
example, a synthetic all-17-types fixture, and the ZIP archive form.

## CLI

`cxf validate <file>` (exit 0 conforms / 1 errors / 2 unusable) and
`cxf inspect <file>` (never prints credential values); both take `--json`.
Real output against the spec's own example payload:

```
$ cxf validate test/fixtures/spec/appendix-a.json
test/fixtures/spec/appendix-a.json: 0 error(s), 5 warning(s)

  warning CXF2003 at $.accounts[0].items[1].credentials[0].fido2Extensions.hmacSecret
    Fido2Extensions has no "hmacSecret" member in CXF v1.0; importers will ignore it.

  warning CXF2004 at $.accounts[0].items[3].credentials[0].networkSecurityType.value
    "WPA2" is not a known value (known: unsecured, wpa-personal, wpa2-personal, wpa3-personal, wep); importers must ignore this member.

  warning CXF2008 at $.accounts[0].items[5].credentials[0].territory.value
    A "subdivision-code" value must be an ISO 3166-2 code like "US-CA", got "CA".

  warning CXF2008 at $.accounts[0].items[6].credentials[0].territory.value
    A "subdivision-code" value must be an ISO 3166-2 code like "US-CA", got "CA".

  warning CXF2009 at $.accounts[0].items[7].credentials[0].expiryDate.extensions
    EditableField has an empty extensions array; the CDDL requires this array to be non-empty when present.

OK: document conforms to CXF v1.0 (5 warning(s)).
```

Yes — every one of those warnings is the spec's example contradicting the spec's
own rules. That's the point of the validator.

```
$ cxf inspect test/fixtures/spec/appendix-a.json
test/fixtures/spec/appendix-a.json
  Exporter:  Exporter app (exporter.example.com), CXF 1.0
  Exported:  2024-01-14T10:40:00.000Z
  Source:    bare JSON document
  Accounts:  1

  Account jane_smith <jane.smith@example.com> (id DZSXp7iBQY-Fg-OofakQtQ)
    Items: 14   Collections: 1
    Credentials:
      address             1
      api-key             1
      basic-auth          1
      credit-card         1
      drivers-license     1
      file                1
      generated-password  1
      identity-document   1
      note                1
      passkey             1
      passport            1
      person-name         1
      ssh-key             1
      totp                1
      wifi                1
```

## Archive form and security notes

The spec defines no on-disk packaging (finding 1), so the kit defines one:
a ZIP with `index.json` (the Header document) and `documents/<fileId>` entries
for `file` credential payloads. Bare `.json` is accepted everywhere; input kind
is sniffed by magic number. Hostile input is expected:

- **Zip-bomb limits** — decompression is capped (default 10,000 entries /
  1 GiB total), checked against both the sizes entries *declare* and what
  actually decompresses (declared sizes can lie). Breach → `CXF1006`.
  Configurable via `parseCxf(bytes, { archiveLimits })`.
- **Path-traversal defense** — `documents/` entry names must be pure base64url
  (`^[A-Za-z0-9_-]+$`): no `..`, no separators, nothing unsafe to reuse as a
  filename. Violations reject the archive (`CXF1008`), and `writeArchive`
  refuses unsafe ids symmetrically.
- **Strict UTF-8** — byte input is decoded with `fatal: true`; invalid UTF-8 is
  a parse error (`CXF1007`), never a silent U+FFFD substitution. In a credential
  format, silently corrupting a secret is worse than failing.
- **Payload integrity** — in archive mode the validator verifies each file
  payload's size and SHA-256 against its credential (`CXF2016`/`CXF2017`).

## Spec findings

Every ambiguity or defect hit while building this kit is logged with its
resolution in [SPEC_NOTES.md](SPEC_NOTES.md). The five that shaped the code:

1. **No on-disk packaging is defined** ([§1](SPEC_NOTES.md)) — the spec scopes
   itself to the JSON payload; the ZIP layout above is kit-defined, not spec.
2. **`WIFINetworkSecurityType` CDDL typo** ([§2](SPEC_NOTES.md)) — declared with
   map braces but plainly a string enum; treated as an enum.
3. **`[ + Extension ] .default []` contradiction** ([§3](SPEC_NOTES.md)) — an
   empty array is simultaneously the default and disallowed; serializer omits in
   normalize mode, validator warns.
4. **Appendix A contradicts the CDDL** ([§11](SPEC_NOTES.md)) — the spec's own
   example carries `fido2Extensions.hmacSecret { algorithm: "HS256" }` (the CDDL
   defines `hmacCredentials` with `"hmac-sha256"`), a present-but-empty
   `extensions` array, bare `"CA"` as a subdivision code, and `"WPA2"` as a wifi
   security type. Real exports imitate examples, so all of these validate as
   warnings, not errors. An upstream report to the FIDO Alliance is planned
   (PLAN.md, post-v0.1).
5. **Review Draft 2025-03 ≡ Proposed Standard 2025-08 on the wire**
   ([§10](SPEC_NOTES.md)) — every CDDL delta between the revisions is an
   editorial typo fix, so interop with RD-targeted implementations (Bitwarden)
   imposes no type differences.

## Fixtures & provenance

Three families, documented in [`test/fixtures/README.md`](test/fixtures/README.md):
the spec's Appendix A verbatim; fragments extracted from Bitwarden's MIT-licensed
[`credential-exchange`](https://github.com/bitwarden/credential-exchange) test
modules (commit-pinned attribution); and a synthetic kitchen-sink covering all 17
credential types plus deliberate unknowns. No genuine Apple exporter output exists
publicly — iOS/macOS 26 transfers credentials only via encrypted app-to-app CXP
sessions, never a readable file.

## License

MIT.
