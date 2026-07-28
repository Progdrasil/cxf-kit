/**
 * Data models for the FIDO Credential Exchange Format (CXF) v1.0,
 * Proposed Standard with errata 2026-03-09. Each type mirrors the wire format 1:1;
 * the authoritative CDDL is vendored at spec/cxf-v1.0-ps-errata-20260309.cddl.
 *
 * Naming follows the CDDL exactly (APIKey, TOTP, WIFI, ...) except
 * `File` -> `FileCredential`, which would otherwise shadow the global.
 */

/**
 * Every enum position in the spec is `KnownEnum / tstr`: exporters may emit
 * values we don't know, and importers must tolerate them. This keeps
 * autocomplete for known values while admitting any string.
 */
export type OpenEnum<K extends string> = K | (string & {});

/** RFC 4648 base64url-encoded bytes, carried as a JSON string. */
export type B64Url = string;

/** Unix timestamp in seconds (CDDL `uint .size 8`). Must be a non-negative safe integer. */
export type UnixSeconds = number;

/** RFC 3986 URI. */
export type Uri = string;

// ---------------------------------------------------------------------------
// Document structure
// ---------------------------------------------------------------------------

/** Root of a CXF export. */
export interface Header {
  version: Version;
  /** Exporting app's relying party identifier. */
  exporterRpId: string;
  /** User-facing name of the exporting app. */
  exporterDisplayName: string;
  /** When the export completed. */
  timestamp: UnixSeconds;
  accounts: Account[];
}

export interface Version {
  /** CDDL `uint .size 1` (0-255). */
  major: number;
  minor: number;
}

/** The version of the spec these models implement. */
export const CXF_VERSION: Version = { major: 1, minor: 0 };

export interface Account {
  /** Machine-generated opaque id; decoded length must be <= 64 bytes. */
  id: B64Url;
  username: string;
  email: string;
  fullName?: string;
  /** Collections owned by this account. Shared-in entities must not appear. */
  collections: Collection[];
  /** Items owned by this account. Shared-in entities must not appear. */
  items: Item[];
  /** Omitted when empty. */
  extensions?: Extension[];
}

export interface Collection {
  /** Decoded length must be <= 64 bytes. */
  id: B64Url;
  creationAt?: UnixSeconds;
  modifiedAt?: UnixSeconds;
  title: string;
  subtitle?: string;
  items: LinkedItem[];
  /** Omitted when empty. */
  subCollections?: Collection[];
  /** Omitted when empty. */
  extensions?: Extension[];
}

/** Reference to an Item, possibly owned by another Account in the export. */
export interface LinkedItem {
  /** The referenced Item's id. */
  item: B64Url;
  /** Owning Account's id; defaults to the enclosing Account. */
  account?: B64Url;
}

export interface Item {
  /** Decoded length must be <= 64 bytes. */
  id: B64Url;
  creationAt?: UnixSeconds;
  modifiedAt?: UnixSeconds;
  title: string;
  subtitle?: string;
  /** Defaults to false; omitted when false. */
  favorite?: boolean;
  /** Does not apply to passkey credentials (their scope is rpId). */
  scope?: CredentialScope;
  credentials: Credential[];
  /** Omitted when empty. */
  tags?: string[];
  /** Omitted when empty. */
  extensions?: Extension[];
}

export interface CredentialScope {
  urls: Uri[];
  androidApps: AndroidAppId[];
}

export interface AndroidAppId {
  /** Application package identifier, e.g. "com.example.app". */
  bundleId: string;
  certificate?: AndroidAppCertificateFingerprint;
  name?: string;
}

export const HASH_ALGS = ["sha256", "sha512"] as const;
export type HashAlg = (typeof HASH_ALGS)[number];

export interface AndroidAppCertificateFingerprint {
  fingerprint: B64Url;
  hashAlg: OpenEnum<HashAlg>;
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export const CREDENTIAL_TYPES = [
  "address",
  "api-key",
  "basic-auth",
  "credit-card",
  "custom-fields",
  "drivers-license",
  "file",
  "generated-password",
  "identity-document",
  "item-reference",
  "note",
  "passkey",
  "passport",
  "person-name",
  "ssh-key",
  "totp",
  "wifi",
] as const;
export type CredentialType = (typeof CREDENTIAL_TYPES)[number];

/**
 * Any credential in an Item. Discriminate on `type`; a credential whose
 * `type` is not in CREDENTIAL_TYPES is an UnknownCredential and must be
 * preserved verbatim for round-tripping (importers ignore, not drop).
 */
export type Credential = KnownCredential | UnknownCredential;

export type KnownCredential =
  | Address
  | APIKey
  | BasicAuth
  | CreditCard
  | CustomFields
  | DriversLicense
  | FileCredential
  | GeneratedPassword
  | IdentityDocument
  | ItemReference
  | Note
  | Passkey
  | Passport
  | PersonName
  | SSHKey
  | TOTP
  | WIFI;

/** A credential of a type this kit doesn't know. Content is preserved as-is. */
export interface UnknownCredential {
  type: string;
  [member: string]: unknown;
}

export interface Address {
  type: "address";
  streetAddress?: EditableField<"string">;
  postalCode?: EditableField<"string">;
  city?: EditableField<"string">;
  territory?: EditableField<"subdivision-code">;
  country?: EditableField<"country-code">;
  tel?: EditableField<"string">;
}

export interface APIKey {
  type: "api-key";
  key?: EditableField<"concealed-string">;
  username?: EditableField<"string">;
  keyType?: EditableField<"string">;
  url?: EditableField<"string">;
  validFrom?: EditableField<"date">;
  expiryDate?: EditableField<"date">;
}

export interface BasicAuth {
  type: "basic-auth";
  username?: EditableField<"string">;
  password?: EditableField<"concealed-string">;
}

export interface CreditCard {
  type: "credit-card";
  number?: EditableField<"concealed-string">;
  fullName?: EditableField<"string">;
  cardType?: EditableField<"string">;
  verificationNumber?: EditableField<"concealed-string">;
  pin?: EditableField<"concealed-string">;
  expiryDate?: EditableField<"year-month">;
  validFrom?: EditableField<"year-month">;
}

export interface CustomFields {
  type: "custom-fields";
  /** Decoded length must be <= 64 bytes. */
  id?: B64Url;
  /** Section title when a provider groups custom fields. */
  label?: string;
  fields: EditableField[];
  /** CDDL says non-empty if present; omitted when empty (SPEC_NOTES #3). */
  extensions?: Extension[];
}

export interface DriversLicense {
  type: "drivers-license";
  fullName?: EditableField<"string">;
  birthDate?: EditableField<"date">;
  issueDate?: EditableField<"date">;
  expiryDate?: EditableField<"date">;
  issuingAuthority?: EditableField<"string">;
  territory?: EditableField<"subdivision-code">;
  country?: EditableField<"country-code">;
  licenseNumber?: EditableField<"string">;
  licenseClass?: EditableField<"string">;
}

/**
 * CDDL name: `File`. Metadata only — the bytes travel out of band (this kit's
 * archive convention stores them at documents/<id>, see PLAN.md).
 */
export interface FileCredential {
  type: "file";
  id: B64Url;
  /** Filename including extension. */
  name: string;
  /** Size in bytes of the decrypted file. */
  decryptedSize: number;
  /** SHA-256 of the decrypted content; importers must verify. */
  integrityHash: B64Url;
}

export interface GeneratedPassword {
  type: "generated-password";
  password: string;
}

export interface IdentityDocument {
  type: "identity-document";
  issuingCountry?: EditableField<"country-code">;
  documentNumber?: EditableField<"string">;
  identificationNumber?: EditableField<"string">;
  nationality?: EditableField<"string">;
  fullName?: EditableField<"string">;
  birthDate?: EditableField<"date">;
  birthPlace?: EditableField<"string">;
  sex?: EditableField<"string">;
  issueDate?: EditableField<"date">;
  expiryDate?: EditableField<"date">;
  issuingAuthority?: EditableField<"string">;
}

export interface ItemReference {
  type: "item-reference";
  reference: LinkedItem;
}

export interface Note {
  type: "note";
  content: EditableField<"string">;
}

export interface Passkey {
  type: "passkey";
  /** WebAuthn credential id. */
  credentialId: B64Url;
  rpId: string;
  /** User-editable, unlike the rest of this structure. */
  username: string;
  /** User-editable, unlike the rest of this structure. */
  userDisplayName: string;
  userHandle: B64Url;
  /** PKCS#8 DER-encoded private key. Signature counter must be zero on export. */
  key: B64Url;
  fido2Extensions?: Fido2Extensions;
}

export interface Fido2Extensions {
  hmacCredentials?: Fido2HmacCredentials;
  credBlob?: B64Url;
  largeBlob?: Fido2LargeBlob;
  payments?: boolean;
}

export const FIDO2_HMAC_CREDENTIAL_ALGORITHMS = ["hmac-sha256"] as const;
export type Fido2HmacCredentialAlgorithm =
  (typeof FIDO2_HMAC_CREDENTIAL_ALGORITHMS)[number];

export interface Fido2HmacCredentials {
  algorithm: OpenEnum<Fido2HmacCredentialAlgorithm>;
  credWithUV: B64Url;
  credWithoutUV: B64Url;
}

export interface Fido2LargeBlob {
  /** Size after DEFLATE decompression of `data`. */
  uncompressedSize: number;
  /** DEFLATE-compressed blob. */
  data: B64Url;
}

export interface Passport {
  type: "passport";
  issuingCountry?: EditableField<"country-code">;
  passportType?: EditableField<"string">;
  passportNumber?: EditableField<"string">;
  nationalIdentificationNumber?: EditableField<"string">;
  nationality?: EditableField<"string">;
  fullName?: EditableField<"string">;
  birthDate?: EditableField<"date">;
  birthPlace?: EditableField<"string">;
  sex?: EditableField<"string">;
  issueDate?: EditableField<"date">;
  expiryDate?: EditableField<"date">;
  issuingAuthority?: EditableField<"string">;
}

export interface PersonName {
  type: "person-name";
  title?: EditableField<"string">;
  given?: EditableField<"string">;
  givenInformal?: EditableField<"string">;
  given2?: EditableField<"string">;
  surnamePrefix?: EditableField<"string">;
  surname?: EditableField<"string">;
  surname2?: EditableField<"string">;
  /** Qualifications/honorifics after the name (e.g. "PhD"), not secrets. */
  credentials?: EditableField<"string">;
  generation?: EditableField<"string">;
}

export interface SSHKey {
  type: "ssh-key";
  /** SSH algorithm name, e.g. "ssh-ed25519", "ssh-rsa". */
  keyType: string;
  /** PKCS#8 DER-encoded private key. */
  privateKey: B64Url;
  keyComment?: string;
  creationDate?: EditableField<"date">;
  expiryDate?: EditableField<"date">;
  keyGenerationSource?: EditableField<"string">;
}

export const OTP_HASH_ALGORITHMS = ["sha1", "sha256", "sha512"] as const;
export type OTPHashAlgorithm = (typeof OTP_HASH_ALGORITHMS)[number];

export interface TOTP {
  type: "totp";
  /** Base32-encoded shared secret (RFC 4648 §6). */
  secret: string;
  /** Time step in seconds (importer default when absent: 30). */
  period: number;
  /** OTP length (importer default when absent: 6). */
  digits: number;
  username?: string;
  /** Importer default when absent: "sha1". */
  algorithm: OpenEnum<OTPHashAlgorithm>;
  issuer?: string;
}

export const WIFI_NETWORK_SECURITY_TYPES = [
  "unsecured",
  "wpa-personal",
  "wpa2-personal",
  "wpa3-personal",
  "wep",
] as const;
export type WIFINetworkSecurityType =
  (typeof WIFI_NETWORK_SECURITY_TYPES)[number];

export interface WIFI {
  type: "wifi";
  ssid?: EditableField<"string">;
  networkSecurityType?: EditableField<"wifi-network-security-type" | "string">;
  passphrase?: EditableField<"concealed-string">;
  hidden?: EditableField<"boolean">;
}

// ---------------------------------------------------------------------------
// EditableField
// ---------------------------------------------------------------------------

export const FIELD_TYPES = [
  "string",
  "concealed-string",
  "email",
  "number",
  "boolean",
  "date",
  "year-month",
  "wifi-network-security-type",
  "country-code",
  "subdivision-code",
] as const;
export type FieldType = (typeof FIELD_TYPES)[number];

/**
 * A user-editable value with display metadata. `F` is the field type the
 * spec prescribes for a given position; the wire always admits any string
 * (unknown fieldType => importer treats the member as absent).
 * The value is always carried as a string, whatever the fieldType.
 */
export interface EditableField<F extends FieldType = FieldType> {
  /** Decoded length must be <= 64 bytes. */
  id?: B64Url;
  fieldType: OpenEnum<F>;
  value: string;
  label?: string;
  /** CDDL says non-empty if present; omitted when empty (SPEC_NOTES #3). */
  extensions?: Extension[];
}

// ---------------------------------------------------------------------------
// Extensions
// ---------------------------------------------------------------------------

/**
 * Open-content extension. Registered extensions use their bare name;
 * custom ones must be named "EXPORTER_RP_ID/EXTENSION_NAME". All members
 * are preserved verbatim for round-tripping.
 */
export interface Extension {
  name: string;
  [member: string]: unknown;
}

/** The only registered extension: sharing metadata on an entity. */
export interface Shared extends Extension {
  name: "shared";
  accessors: SharingAccessor[];
}

export const SHARING_ACCESSOR_TYPES = ["user", "group"] as const;
export type SharingAccessorType = (typeof SHARING_ACCESSOR_TYPES)[number];

export const SHARING_ACCESSOR_PERMISSIONS = [
  "read",
  "readSecret",
  "update",
  "create",
  "delete",
  "share",
  "manage",
] as const;
export type SharingAccessorPermission =
  (typeof SHARING_ACCESSOR_PERMISSIONS)[number];

export interface SharingAccessor {
  /** Entries with an unknown type are ignored by importers. */
  type: OpenEnum<SharingAccessorType>;
  /** The Account id given access. */
  accountId: B64Url;
  /** Username (type "user") or group name (type "group"). */
  name: string;
  /** Unknown entries ignored; an accessor left with no permissions is ignored. */
  permissions: OpenEnum<SharingAccessorPermission>[];
}
