# SPEC_NOTES — ambiguities found in CXF v1.0 PS (2025-08-14) and how this kit resolves them

Ground truth: `spec/cxf-v1.0-ps-20250814.cddl` (extracted verbatim from the spec's CDDL Index).
Each entry: what the spec says (or doesn't), why it's ambiguous, and the resolution taken here.
**Resolutions marked ⚠ were decided by the kit, not the spec — review welcome.**

## 1. ⚠ No on-disk packaging / archive format defined
The spec scopes itself to data structures only: "does not make any assumptions about the
protocol used for the transfer." `File` credentials carry `id`/`name`/`decryptedSize`/`integrityHash`
but the spec never says where the bytes live in an export.
**Resolution:** kit-defined ZIP convention — `index.json` (Header document) + `documents/<fileId>`
entries. Bare JSON files accepted everywhere. Documented in PLAN.md; not claimed to be spec.

## 2. ⚠ `WIFINetworkSecurityType` CDDL typo
Written as `WIFINetworkSecurityType = { "unsecured" / ... }` — braces make it a map in CDDL,
but it's plainly meant as a string enum (every other enum uses bare alternation, and
`EditableField<"wifi-network-security-type">` carries a string `value`).
**Resolution:** treated as a string enum: `unsecured | wpa-personal | wpa2-personal | wpa3-personal | wep`.

## 3. ⚠ `[ + Extension ] .default []` contradiction
`CustomFields.extensions` and `EditableField.extensions` use `+` (one-or-more) yet default to `[]`.
Entity-level `extensions` (Account/Collection/Item) use `*` (zero-or-more). Contradictory: an
empty array is simultaneously the default and disallowed.
**Resolution:** serializer omits empty `extensions` everywhere; validator emits a **warning**
(not error) if a present `extensions` array is empty on CustomFields/EditableField.

## 4. Open enums everywhere
Every enum position is `KnownEnum / tstr`, and the spec's processing rules say: unknown value in
an *optional* member ⇒ ignore the member; in a *required* member ⇒ ignore the whole structure.
**Resolution:** types use `Known | (string & {})`; unknown enum values are parse-preserved and
reported as validator **warnings** with the spec's prescribed importer behavior in the message.

## 5. Identifier length "≤ 64 bytes"
`b64url = tstr` in CDDL carries no length; the prose caps ids (Account/Collection/Item/
CustomFields/EditableField ids) at 64 bytes — of *decoded* data.
**Resolution:** validator decodes and checks ≤ 64 bytes on id fields specifically; other b64url
fields (keys, hashes, blobs) get validity-only checks.

## 6. Required-vs-optional empty arrays
CDDL: required arrays (`accounts`, `items`, `credentials`, `urls`, `fields`, ...) may be present-empty;
optional arrays carry `.default []`, and the prose says exporters omit them when empty.
**Resolution:** serializer always emits required arrays (even empty) and omits optional arrays
when empty; validator warns on present-but-empty optional arrays (style, not conformance error).

## 7. `uint .size 8` timestamps vs JSON numbers
Unix-seconds timestamps are 8-byte uints, but JS `number` is exact only to 2^53−1. Real
timestamps are ~2^31 so this is theoretical.
**Resolution:** modeled as `number`; validator errors if a timestamp is not a non-negative
safe integer.

## 8. TOTP required members vs importer defaults
CDDL marks `secret`, `period`, `digits`, `algorithm` all required; prose elsewhere gives importer
defaults (period 30, digits 6, sha1) for tolerating absent members.
**Resolution:** validator flags missing `period`/`digits`/`algorithm` as **warnings** noting the
prescribed default, and missing `secret` as an **error** (no default exists; credential is unusable).

## 9. `Extension` content is open
`Extension = $Extension .within { name: tstr }`; only `shared` is registered. The CDDL itself
contains the drafters' open question ("Should there be an included schema?"). Custom extension
names MUST be `EXPORTER_RP_ID/EXTENSION_NAME`.
**Resolution:** modeled as `{ name: string } & { [key: string]: unknown }` with a typed
`SharedExtension` narrowing; validator warns when a non-registered extension name lacks the
`RP_ID/NAME` shape. All extension content is round-trip preserved.

## 10. ⚠ Fetch-summary hazard (process note, not spec)
Two independent LLM summaries of the spec both mis-stated `SharingAccessor`'s fields
(claimed `identifier`/`createdDate`/`permission`); the real CDDL has
`type`, `accountId`, `name`, `permissions[]`. All models here were built from the raw
extracted CDDL, not summaries.
