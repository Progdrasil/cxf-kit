# Test fixtures — provenance

## spec/appendix-a.json
Verbatim from **Appendix A: Example Payload** of the FIDO CXF v1.0 Proposed Standard
(2025-08-14), https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html.
Covers 15 of 17 credential types (no `custom-fields`, no `item-reference`).
Known deviation from the spec's own CDDL (see SPEC_NOTES.md): the passkey's
`fido2Extensions` carries `hmacSecret: { algorithm: "HS256", secret }`, which is not
the CDDL's `hmacCredentials` structure. Kept verbatim — real-world importers will meet
payloads modeled on this example, and the parser must preserve it.

## interop/bitwarden/
JSON payloads extracted verbatim from test modules of
https://github.com/bitwarden/credential-exchange (MIT license), commit
`b8a05e735906226726b98042135286c000e376a5`, crate `credential-exchange-format`:

- `custom-fields.serialize.json` — `src/document.rs`, `test_serialize_custom_fields`.
- `custom-fields.deserialize.json` — `src/document.rs`, `test_deserialize_custom_fields`.
- `unknown-credential.json` — `src/lib.rs`, `deserializes_unknown_credential`.

The `custom-fields.*` fragments have no `"type"` member on disk: Bitwarden's tests
serialize the inner struct, and the `type` tag is added by their `Credential` enum
wrapper. Tests here add `"type": "custom-fields"` when embedding them into an Item.
The repo's `editable_field.rs` fragments were reviewed and skipped as trivial
(three-member EditableField objects already covered elsewhere).

## synthetic/kitchen-sink.json
Authored for this kit. Exercises everything the other fixtures don't: all 17
credential types including `custom-fields` and `item-reference`, an unknown
credential type, unknown enum values, the `shared` extension, a custom
(`RP_ID/NAME`) extension, `subCollections`, cross-account `LinkedItem`s, and a
`file` credential whose bytes live in the ZIP archive form (built in-memory by
`test/parse.test.ts`; the archive itself is not committed).

## Apple exporter output
None available: Apple (iOS/macOS 26, `ASCredentialExportManager`) performs CXF
transfers only via encrypted app-to-app CXP sessions and never produces a
user-readable export file, so no genuine sample can be obtained publicly.
Re-check if Apple ever ships file-based export.
