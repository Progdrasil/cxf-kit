/**
 * Runtime type guards for the CXF data models.
 *
 * `Credential` is `KnownCredential | UnknownCredential`, and because
 * `UnknownCredential.type` is `string`, a bare `c.type === "passkey"` check
 * narrows only to `Passkey | UnknownCredential`. Route through
 * isKnownCredential / credentialOfType first; afterwards the known union
 * discriminates normally.
 *
 * Guards here check the discriminant (plus minimal structure where the
 * discriminant alone would lie, e.g. Shared). Full structural checking is
 * the validator's job, not theirs.
 */

import {
  CREDENTIAL_TYPES,
  FIELD_TYPES,
  OTP_HASH_ALGORITHMS,
  SHARING_ACCESSOR_PERMISSIONS,
  SHARING_ACCESSOR_TYPES,
  WIFI_NETWORK_SECURITY_TYPES,
} from "./types.js";
import type {
  Address,
  APIKey,
  BasicAuth,
  Credential,
  CredentialType,
  CreditCard,
  CustomFields,
  DriversLicense,
  Extension,
  FieldType,
  FileCredential,
  GeneratedPassword,
  IdentityDocument,
  ItemReference,
  KnownCredential,
  Note,
  OTPHashAlgorithm,
  Passkey,
  Passport,
  PersonName,
  Shared,
  SharingAccessorPermission,
  SharingAccessorType,
  SSHKey,
  TOTP,
  UnknownCredential,
  WIFI,
  WIFINetworkSecurityType,
} from "./types.js";

/** Maps each credential type string to its credential interface. */
export interface CredentialTypeMap {
  "address": Address;
  "api-key": APIKey;
  "basic-auth": BasicAuth;
  "credit-card": CreditCard;
  "custom-fields": CustomFields;
  "drivers-license": DriversLicense;
  "file": FileCredential;
  "generated-password": GeneratedPassword;
  "identity-document": IdentityDocument;
  "item-reference": ItemReference;
  "note": Note;
  "passkey": Passkey;
  "passport": Passport;
  "person-name": PersonName;
  "ssh-key": SSHKey;
  "totp": TOTP;
  "wifi": WIFI;
}

export function isKnownCredentialType(type: string): type is CredentialType {
  return (CREDENTIAL_TYPES as readonly string[]).includes(type);
}

export function isKnownCredential(c: Credential): c is KnownCredential {
  return isKnownCredentialType(c.type);
}

export function isUnknownCredential(c: Credential): c is UnknownCredential {
  return !isKnownCredentialType(c.type);
}

/**
 * Discriminate a Credential to one concrete type in a single step:
 *
 *   if (credentialOfType(c, "passkey")) c.rpId;
 */
export function credentialOfType<K extends CredentialType>(
  c: Credential,
  type: K,
): c is CredentialTypeMap[K] {
  return c.type === type;
}

/**
 * True when the extension is the registered "shared" extension carrying an
 * accessors array. Name alone is not trusted: extension content is open, so
 * a malformed "shared" without accessors stays a plain Extension here and
 * gets reported by the validator instead.
 */
export function isSharedExtension(e: Extension): e is Shared {
  return e.name === "shared" && Array.isArray(e["accessors"]);
}

export function isKnownFieldType(value: string): value is FieldType {
  return (FIELD_TYPES as readonly string[]).includes(value);
}

export function isKnownOTPHashAlgorithm(
  value: string,
): value is OTPHashAlgorithm {
  return (OTP_HASH_ALGORITHMS as readonly string[]).includes(value);
}

export function isKnownWIFINetworkSecurityType(
  value: string,
): value is WIFINetworkSecurityType {
  return (WIFI_NETWORK_SECURITY_TYPES as readonly string[]).includes(value);
}

export function isKnownSharingAccessorType(
  value: string,
): value is SharingAccessorType {
  return (SHARING_ACCESSOR_TYPES as readonly string[]).includes(value);
}

export function isKnownSharingAccessorPermission(
  value: string,
): value is SharingAccessorPermission {
  return (SHARING_ACCESSOR_PERMISSIONS as readonly string[]).includes(value);
}
