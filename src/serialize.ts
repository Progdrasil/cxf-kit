/**
 * Spec-compliant CXF serialization.
 *
 * Output rules:
 * - Known members in CDDL declaration order; unknown members afterwards in
 *   insertion order, preserved verbatim (never dropped).
 * - By default nothing is removed or invented: parse -> serialize -> parse is
 *   value-identical for ANY input, even nonconforming ones (the spec's own
 *   Appendix A carries an empty optional `extensions` array, see SPEC_NOTES).
 *   With `normalize: true`, optional arrays with CDDL `.default []`
 *   (extensions, subCollections, tags) are omitted when empty, as the spec
 *   requires of exporters; the validator warns (CXF2009) when a document
 *   needs that normalization.
 * - Credentials with unknown types and extension bodies are passed through
 *   untouched (except the registered "shared" extension, whose accessors are
 *   ordered like any known structure).
 */

import { writeArchive } from "./archive.js";
import { isKnownCredentialType } from "./guards.js";
import type { CxfDocument } from "./parse.js";
import type { CredentialType, Header } from "./types.js";

type Json = Record<string, unknown>;

interface NodeSpec {
  order: readonly string[];
  /** Member name -> child node; wrap in [] for arrays of that node. */
  children?: Record<string, string | readonly [string]>;
  /** Members dropped when they are present-but-empty arrays. */
  omitEmptyArrays?: readonly string[];
}

const EF = "EditableField";

/** children entry for a credential whose listed members are all EditableFields. */
function efChildren(...keys: string[]): Record<string, string> {
  return Object.fromEntries(keys.map((k) => [k, EF]));
}

const SPECS: Record<string, NodeSpec> = {
  Header: {
    order: ["version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"],
    children: { version: "Version", accounts: ["Account"] },
  },
  Version: { order: ["major", "minor"] },
  Account: {
    order: ["id", "username", "email", "fullName", "collections", "items", "extensions"],
    children: { collections: ["Collection"], items: ["Item"], extensions: ["Extension"] },
    omitEmptyArrays: ["extensions"],
  },
  Collection: {
    order: [
      "id",
      "creationAt",
      "modifiedAt",
      "title",
      "subtitle",
      "items",
      "subCollections",
      "extensions",
    ],
    children: {
      items: ["LinkedItem"],
      subCollections: ["Collection"],
      extensions: ["Extension"],
    },
    omitEmptyArrays: ["subCollections", "extensions"],
  },
  LinkedItem: { order: ["item", "account"] },
  Item: {
    order: [
      "id",
      "creationAt",
      "modifiedAt",
      "title",
      "subtitle",
      "favorite",
      "scope",
      "credentials",
      "tags",
      "extensions",
    ],
    children: {
      scope: "CredentialScope",
      credentials: ["Credential"],
      extensions: ["Extension"],
    },
    omitEmptyArrays: ["tags", "extensions"],
  },
  CredentialScope: {
    order: ["urls", "androidApps"],
    children: { androidApps: ["AndroidAppId"] },
  },
  AndroidAppId: {
    order: ["bundleId", "certificate", "name"],
    children: { certificate: "AndroidAppCertificateFingerprint" },
  },
  AndroidAppCertificateFingerprint: { order: ["fingerprint", "hashAlg"] },
  [EF]: {
    order: ["id", "fieldType", "value", "label", "extensions"],
    children: { extensions: ["Extension"] },
    omitEmptyArrays: ["extensions"],
  },
  Fido2Extensions: {
    order: ["hmacCredentials", "credBlob", "largeBlob", "payments"],
    children: { hmacCredentials: "Fido2HmacCredentials", largeBlob: "Fido2LargeBlob" },
  },
  Fido2HmacCredentials: { order: ["algorithm", "credWithUV", "credWithoutUV"] },
  Fido2LargeBlob: { order: ["uncompressedSize", "data"] },
  SharingAccessor: { order: ["type", "accountId", "name", "permissions"] },
};

const CREDENTIAL_SPECS: Record<CredentialType, NodeSpec> = {
  "address": {
    order: ["type", "streetAddress", "postalCode", "city", "territory", "country", "tel"],
    children: efChildren("streetAddress", "postalCode", "city", "territory", "country", "tel"),
  },
  "api-key": {
    order: ["type", "key", "username", "keyType", "url", "validFrom", "expiryDate"],
    children: efChildren("key", "username", "keyType", "url", "validFrom", "expiryDate"),
  },
  "basic-auth": {
    order: ["type", "username", "password"],
    children: efChildren("username", "password"),
  },
  "credit-card": {
    order: [
      "type",
      "number",
      "fullName",
      "cardType",
      "verificationNumber",
      "pin",
      "expiryDate",
      "validFrom",
    ],
    children: efChildren(
      "number",
      "fullName",
      "cardType",
      "verificationNumber",
      "pin",
      "expiryDate",
      "validFrom",
    ),
  },
  "custom-fields": {
    order: ["type", "id", "label", "fields", "extensions"],
    children: { fields: [EF], extensions: ["Extension"] },
    omitEmptyArrays: ["extensions"],
  },
  "drivers-license": {
    order: [
      "type",
      "fullName",
      "birthDate",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
      "territory",
      "country",
      "licenseNumber",
      "licenseClass",
    ],
    children: efChildren(
      "fullName",
      "birthDate",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
      "territory",
      "country",
      "licenseNumber",
      "licenseClass",
    ),
  },
  "file": { order: ["type", "id", "name", "decryptedSize", "integrityHash"] },
  "generated-password": { order: ["type", "password"] },
  "identity-document": {
    order: [
      "type",
      "issuingCountry",
      "documentNumber",
      "identificationNumber",
      "nationality",
      "fullName",
      "birthDate",
      "birthPlace",
      "sex",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
    ],
    children: efChildren(
      "issuingCountry",
      "documentNumber",
      "identificationNumber",
      "nationality",
      "fullName",
      "birthDate",
      "birthPlace",
      "sex",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
    ),
  },
  "item-reference": {
    order: ["type", "reference"],
    children: { reference: "LinkedItem" },
  },
  "note": { order: ["type", "content"], children: efChildren("content") },
  "passkey": {
    order: [
      "type",
      "credentialId",
      "rpId",
      "username",
      "userDisplayName",
      "userHandle",
      "key",
      "fido2Extensions",
    ],
    children: { fido2Extensions: "Fido2Extensions" },
  },
  "passport": {
    order: [
      "type",
      "issuingCountry",
      "passportType",
      "passportNumber",
      "nationalIdentificationNumber",
      "nationality",
      "fullName",
      "birthDate",
      "birthPlace",
      "sex",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
    ],
    children: efChildren(
      "issuingCountry",
      "passportType",
      "passportNumber",
      "nationalIdentificationNumber",
      "nationality",
      "fullName",
      "birthDate",
      "birthPlace",
      "sex",
      "issueDate",
      "expiryDate",
      "issuingAuthority",
    ),
  },
  "person-name": {
    order: [
      "type",
      "title",
      "given",
      "givenInformal",
      "given2",
      "surnamePrefix",
      "surname",
      "surname2",
      "credentials",
      "generation",
    ],
    children: efChildren(
      "title",
      "given",
      "givenInformal",
      "given2",
      "surnamePrefix",
      "surname",
      "surname2",
      "credentials",
      "generation",
    ),
  },
  "ssh-key": {
    order: [
      "type",
      "keyType",
      "privateKey",
      "keyComment",
      "creationDate",
      "expiryDate",
      "keyGenerationSource",
    ],
    children: efChildren("creationDate", "expiryDate", "keyGenerationSource"),
  },
  "totp": {
    order: ["type", "secret", "period", "digits", "username", "algorithm", "issuer"],
  },
  "wifi": {
    order: ["type", "ssid", "networkSecurityType", "passphrase", "hidden"],
    children: efChildren("ssid", "networkSecurityType", "passphrase", "hidden"),
  },
};

function isJsonObject(value: unknown): value is Json {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonNode(value: unknown, node: string | readonly [string], normalize: boolean): unknown {
  if (Array.isArray(node)) {
    return Array.isArray(value) ? value.map((v) => canonNode(v, node[0]!, normalize)) : value;
  }
  if (!isJsonObject(value)) return value;
  if (node === "Credential") return canonCredential(value, normalize);
  if (node === "Extension") return canonExtension(value, normalize);
  const spec = SPECS[node as string];
  return spec ? canonWithSpec(value, spec, normalize) : value;
}

function canonWithSpec(obj: Json, spec: NodeSpec, normalize: boolean): Json {
  const out: Json = {};
  for (const key of spec.order) {
    if (!(key in obj)) continue;
    const value = obj[key];
    if (
      normalize &&
      spec.omitEmptyArrays?.includes(key) &&
      Array.isArray(value) &&
      value.length === 0
    ) {
      continue;
    }
    const child = spec.children?.[key];
    out[key] = child ? canonNode(value, child, normalize) : value;
  }
  for (const key of Object.keys(obj)) {
    if (!spec.order.includes(key)) out[key] = obj[key];
  }
  return out;
}

function canonCredential(cred: Json, normalize: boolean): Json {
  const type = cred["type"];
  if (typeof type !== "string" || !isKnownCredentialType(type)) return cred;
  return canonWithSpec(cred, CREDENTIAL_SPECS[type], normalize);
}

function canonExtension(ext: Json, normalize: boolean): Json {
  // Open content: only "shared" has a structure we know how to order.
  if (ext["name"] === "shared" && Array.isArray(ext["accessors"])) {
    return canonWithSpec(
      ext,
      { order: ["name", "accessors"], children: { accessors: ["SharingAccessor"] } },
      normalize,
    );
  }
  const out: Json = {};
  if ("name" in ext) out["name"] = ext["name"];
  for (const key of Object.keys(ext)) if (key !== "name") out[key] = ext[key];
  return out;
}

export interface SerializeOptions {
  /** JSON indentation; 0 for compact output. Default 2. */
  indent?: number;
  /**
   * Apply the spec's exporter normalizations (omit optional-and-empty
   * arrays). Off by default so round-trips are value-identical even for
   * nonconforming input.
   */
  normalize?: boolean;
}

/** Serialize a Header to spec-compliant JSON text. */
export function serializeCxf(header: Header, options: SerializeOptions = {}): string {
  const indent = options.indent ?? 2;
  return JSON.stringify(
    canonNode(header, "Header", options.normalize ?? false),
    null,
    indent === 0 ? undefined : indent,
  );
}

/** Serialize a document to the kit's ZIP export-archive form. */
export function serializeCxfArchive(
  document: Pick<CxfDocument, "header" | "files">,
  options: SerializeOptions = {},
): Uint8Array {
  return writeArchive(serializeCxf(document.header, options), document.files);
}
