/**
 * CXF conformance validator. Works on raw parsed JSON (`unknown`) so it can
 * report on nonconforming documents that the type system couldn't honestly
 * describe; `parseCxf` + `validateCxf` together are the checked import path.
 *
 * Severity policy: violations of CDDL structure are errors; things the spec
 * tells importers to tolerate (unknown enum values, unknown members, missing
 * TOTP members with defined defaults) are warnings, as are format slips the
 * spec's own Appendix A commits (bare "CA" subdivision codes, "WPA2").
 */

import { createHash } from "node:crypto";
import type { Diagnostic, Severity } from "./diagnostics.js";
import { isKnownCredentialType, isKnownFieldType } from "./guards.js";
import type { CxfDocument } from "./parse.js";
import type { FieldType } from "./types.js";
import {
  FIDO2_HMAC_CREDENTIAL_ALGORITHMS,
  HASH_ALGS,
  OTP_HASH_ALGORITHMS,
  SHARING_ACCESSOR_PERMISSIONS,
  SHARING_ACCESSOR_TYPES,
  WIFI_NETWORK_SECURITY_TYPES,
} from "./types.js";

/** Every code the validator can emit, with its meaning. */
export const DIAGNOSTIC_CODES = {
  CXF2001: "required member missing",
  CXF2002: "member has the wrong JSON type",
  CXF2003: "unknown member on a closed structure",
  CXF2004: "unknown enum value",
  CXF2005: "invalid base64url",
  CXF2006: "identifier longer than 64 decoded bytes",
  CXF2007: "invalid timestamp",
  CXF2008: "value does not match its fieldType format",
  CXF2009: "optional array present but empty",
  CXF2010: "reference to an item or account not in this export",
  CXF2011: "duplicate identifier",
  CXF2012: "custom extension name not in RP_ID/NAME form",
  CXF2013: "sharing accessor entry importers will ignore",
  CXF2014: "required TOTP member missing (importer default exists)",
  CXF2015: "unsupported format version",
  CXF2016: "file payload does not match its credential",
  CXF2017: "file payload missing from archive",
  CXF2018: "integer out of range",
  CXF2019: "key is not plausibly PKCS#8 DER",
  CXF2020: "document root is not an object",
  CXF2021: "fieldType differs from the one the spec prescribes here",
} as const;

export type DiagnosticCode = keyof typeof DIAGNOSTIC_CODES;

export interface ValidateOptions {
  /** File payloads by File.id; enables archive consistency checks. */
  files?: ReadonlyMap<string, Uint8Array> | undefined;
  /** Only "archive" sources are expected to carry file payloads. */
  source?: "json" | "archive" | undefined;
}

export function validateCxf(root: unknown, options: ValidateOptions = {}): Diagnostic[] {
  const ctx = new Ctx(options);
  if (!isObj(root)) {
    ctx.report("error", "CXF2020", "$", `A CXF document must be a JSON object, got ${kindOf(root)}.`);
    return ctx.diagnostics;
  }
  validateHeader(ctx, root);
  return ctx.diagnostics;
}

export function validateDocument(document: CxfDocument): Diagnostic[] {
  return validateCxf(document.header, { files: document.files, source: document.source });
}

// ---------------------------------------------------------------------------

type Json = Record<string, unknown>;
type Kind = "string" | "number" | "boolean" | "array" | "object";

class Ctx {
  diagnostics: Diagnostic[] = [];
  constructor(readonly options: ValidateOptions) {}

  report(severity: Severity, code: DiagnosticCode, path: string, message: string): void {
    this.diagnostics.push({ severity, code, path, message });
  }
}

function isObj(v: unknown): v is Json {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function kindOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  return typeof v;
}

interface MemberRule {
  kind: Kind;
  required?: boolean;
}

/**
 * Checks presence and JSON type of members; warns on members the structure
 * doesn't define. Returns true when all *required* members are usable.
 */
function checkMembers(
  ctx: Ctx,
  obj: Json,
  path: string,
  what: string,
  rules: Record<string, MemberRule>,
): boolean {
  let ok = true;
  for (const [name, rule] of Object.entries(rules)) {
    const value = obj[name];
    if (!(name in obj)) {
      if (rule.required) {
        ctx.report("error", "CXF2001", path, `${what} is missing its required "${name}" member.`);
        ok = false;
      }
      continue;
    }
    if (kindOf(value) !== rule.kind) {
      ctx.report(
        "error",
        "CXF2002",
        `${path}.${name}`,
        `${what} member "${name}" must be a ${rule.kind}, got ${kindOf(value)}.`,
      );
      if (rule.required) ok = false;
    }
  }
  for (const name of Object.keys(obj)) {
    if (!(name in rules)) {
      ctx.report(
        "warning",
        "CXF2003",
        `${path}.${name}`,
        `${what} has no "${name}" member in CXF v1.0; importers will ignore it.`,
      );
    }
  }
  return ok;
}

const B64URL_RE = /^[A-Za-z0-9_-]*$/;

function vB64url(ctx: Ctx, value: unknown, path: string, opts: { id?: boolean } = {}): boolean {
  if (typeof value !== "string") return false; // typed elsewhere
  if (!B64URL_RE.test(value)) {
    ctx.report(
      "error",
      "CXF2005",
      path,
      `"${truncate(value)}" is not unpadded base64url (allowed characters: A-Z a-z 0-9 - _).`,
    );
    return false;
  }
  if (opts.id && Math.floor((value.length * 3) / 4) > 64) {
    ctx.report(
      "error",
      "CXF2006",
      path,
      `Identifier decodes to more than 64 bytes (${Math.floor((value.length * 3) / 4)}); the spec caps ids at 64.`,
    );
  }
  return true;
}

function vTimestamp(ctx: Ctx, value: unknown, path: string): void {
  if (typeof value !== "number") return;
  if (!Number.isSafeInteger(value) || value < 0) {
    ctx.report(
      "error",
      "CXF2007",
      path,
      `Timestamps are non-negative Unix seconds; ${value} is not a non-negative safe integer.`,
    );
  }
}

function vUint(ctx: Ctx, value: unknown, path: string, max: number, what: string): void {
  if (typeof value !== "number") return;
  if (!Number.isInteger(value) || value < 0 || value > max) {
    ctx.report("error", "CXF2018", path, `${what} must be an integer in [0, ${max}], got ${value}.`);
  }
}

function vEnum(
  ctx: Ctx,
  value: unknown,
  path: string,
  table: readonly string[],
  opts: { requiredMember: boolean; structure: string },
): void {
  if (typeof value !== "string" || table.includes(value)) return;
  const behavior = opts.requiredMember
    ? `importers must ignore the whole ${opts.structure}`
    : "importers must ignore this member";
  ctx.report(
    "warning",
    "CXF2004",
    path,
    `"${value}" is not a known value (known: ${table.join(", ")}); ${behavior}.`,
  );
}

function truncate(s: string): string {
  return s.length > 40 ? `${s.slice(0, 37)}...` : s;
}

// ---------------------------------------------------------------------------
// Header / Account / Collection / Item
// ---------------------------------------------------------------------------

function validateHeader(ctx: Ctx, root: Json): void {
  checkMembers(ctx, root, "$", "Header", {
    version: { kind: "object", required: true },
    exporterRpId: { kind: "string", required: true },
    exporterDisplayName: { kind: "string", required: true },
    timestamp: { kind: "number", required: true },
    accounts: { kind: "array", required: true },
  });
  if (isObj(root["version"])) {
    const version = root["version"];
    checkMembers(ctx, version, "$.version", "Version", {
      major: { kind: "number", required: true },
      minor: { kind: "number", required: true },
    });
    vUint(ctx, version["major"], "$.version.major", 255, "version.major");
    vUint(ctx, version["minor"], "$.version.minor", 255, "version.minor");
    if (typeof version["major"] === "number" && version["major"] !== 1) {
      ctx.report(
        "warning",
        "CXF2015",
        "$.version.major",
        `This kit implements CXF 1.x; version ${version["major"]} documents may not be understood.`,
      );
    }
  }
  vTimestamp(ctx, root["timestamp"], "$.timestamp");

  if (!Array.isArray(root["accounts"])) return;
  const accounts = root["accounts"];

  // Reference table for LinkedItem resolution and duplicate detection.
  const itemsByAccount = new Map<string, Set<string>>();
  for (const account of accounts) {
    if (!isObj(account) || typeof account["id"] !== "string") continue;
    if (itemsByAccount.has(account["id"])) {
      ctx.report(
        "error",
        "CXF2011",
        "$.accounts",
        `Account id "${account["id"]}" appears more than once.`,
      );
    }
    const ids = new Set<string>();
    if (Array.isArray(account["items"])) {
      for (const item of account["items"]) {
        if (isObj(item) && typeof item["id"] === "string") ids.add(item["id"]);
      }
    }
    itemsByAccount.set(account["id"], ids);
  }

  accounts.forEach((account, i) => {
    const path = `$.accounts[${i}]`;
    if (!isObj(account)) {
      ctx.report("error", "CXF2002", path, `Accounts must be objects, got ${kindOf(account)}.`);
      return;
    }
    validateAccount(ctx, account, path, itemsByAccount);
  });
}

function validateAccount(ctx: Ctx, account: Json, path: string, refs: Map<string, Set<string>>): void {
  checkMembers(ctx, account, path, "Account", {
    id: { kind: "string", required: true },
    username: { kind: "string", required: true },
    email: { kind: "string", required: true },
    fullName: { kind: "string" },
    collections: { kind: "array", required: true },
    items: { kind: "array", required: true },
    extensions: { kind: "array" },
  });
  vB64url(ctx, account["id"], `${path}.id`, { id: true });
  const accountId = typeof account["id"] === "string" ? account["id"] : undefined;

  if (Array.isArray(account["items"])) {
    const seen = new Set<string>();
    account["items"].forEach((item, i) => {
      const itemPath = `${path}.items[${i}]`;
      if (!isObj(item)) {
        ctx.report("error", "CXF2002", itemPath, `Items must be objects, got ${kindOf(item)}.`);
        return;
      }
      if (typeof item["id"] === "string") {
        if (seen.has(item["id"])) {
          ctx.report("error", "CXF2011", `${itemPath}.id`, `Item id "${item["id"]}" appears more than once in this account.`);
        }
        seen.add(item["id"]);
      }
      validateItem(ctx, item, itemPath, accountId, refs);
    });
  }

  if (Array.isArray(account["collections"])) {
    const seen = new Set<string>();
    account["collections"].forEach((coll, i) => {
      validateCollection(ctx, coll, `${path}.collections[${i}]`, accountId, refs, seen);
    });
  }

  vExtensions(ctx, account["extensions"], `${path}.extensions`, "Account");
}

function validateCollection(
  ctx: Ctx,
  coll: unknown,
  path: string,
  accountId: string | undefined,
  refs: Map<string, Set<string>>,
  seenIds: Set<string>,
): void {
  if (!isObj(coll)) {
    ctx.report("error", "CXF2002", path, `Collections must be objects, got ${kindOf(coll)}.`);
    return;
  }
  checkMembers(ctx, coll, path, "Collection", {
    id: { kind: "string", required: true },
    creationAt: { kind: "number" },
    modifiedAt: { kind: "number" },
    title: { kind: "string", required: true },
    subtitle: { kind: "string" },
    items: { kind: "array", required: true },
    subCollections: { kind: "array" },
    extensions: { kind: "array" },
  });
  vB64url(ctx, coll["id"], `${path}.id`, { id: true });
  if (typeof coll["id"] === "string") {
    if (seenIds.has(coll["id"])) {
      ctx.report("error", "CXF2011", `${path}.id`, `Collection id "${coll["id"]}" appears more than once in this account.`);
    }
    seenIds.add(coll["id"]);
  }
  vTimestamp(ctx, coll["creationAt"], `${path}.creationAt`);
  vTimestamp(ctx, coll["modifiedAt"], `${path}.modifiedAt`);

  if (Array.isArray(coll["items"])) {
    coll["items"].forEach((li, i) => vLinkedItem(ctx, li, `${path}.items[${i}]`, accountId, refs));
  }
  if (Array.isArray(coll["subCollections"])) {
    if (coll["subCollections"].length === 0) {
      ctx.report("warning", "CXF2009", `${path}.subCollections`, "Optional arrays should be omitted when empty.");
    }
    coll["subCollections"].forEach((sub, i) =>
      validateCollection(ctx, sub, `${path}.subCollections[${i}]`, accountId, refs, seenIds),
    );
  }
  vExtensions(ctx, coll["extensions"], `${path}.extensions`, "Collection");
}

function vLinkedItem(
  ctx: Ctx,
  li: unknown,
  path: string,
  accountId: string | undefined,
  refs: Map<string, Set<string>>,
): void {
  if (!isObj(li)) {
    ctx.report("error", "CXF2002", path, `LinkedItems must be objects, got ${kindOf(li)}.`);
    return;
  }
  checkMembers(ctx, li, path, "LinkedItem", {
    item: { kind: "string", required: true },
    account: { kind: "string" },
  });
  vB64url(ctx, li["item"], `${path}.item`);
  if ("account" in li) vB64url(ctx, li["account"], `${path}.account`);

  if (typeof li["item"] !== "string") return;
  const targetAccount = typeof li["account"] === "string" ? li["account"] : accountId;
  if (targetAccount === undefined) return;
  const items = refs.get(targetAccount);
  if (items === undefined) {
    ctx.report("error", "CXF2010", `${path}.account`, `Referenced account "${targetAccount}" is not in this export.`);
  } else if (!items.has(li["item"])) {
    ctx.report(
      "error",
      "CXF2010",
      `${path}.item`,
      `Referenced item "${li["item"]}" is not in account "${targetAccount}".`,
    );
  }
}

function validateItem(
  ctx: Ctx,
  item: Json,
  path: string,
  accountId: string | undefined,
  refs: Map<string, Set<string>>,
): void {
  checkMembers(ctx, item, path, "Item", {
    id: { kind: "string", required: true },
    creationAt: { kind: "number" },
    modifiedAt: { kind: "number" },
    title: { kind: "string", required: true },
    subtitle: { kind: "string" },
    favorite: { kind: "boolean" },
    scope: { kind: "object" },
    credentials: { kind: "array", required: true },
    tags: { kind: "array" },
    extensions: { kind: "array" },
  });
  vB64url(ctx, item["id"], `${path}.id`, { id: true });
  vTimestamp(ctx, item["creationAt"], `${path}.creationAt`);
  vTimestamp(ctx, item["modifiedAt"], `${path}.modifiedAt`);

  if (isObj(item["scope"])) vScope(ctx, item["scope"], `${path}.scope`);

  if (Array.isArray(item["tags"])) {
    if (item["tags"].length === 0) {
      ctx.report("warning", "CXF2009", `${path}.tags`, "Optional arrays should be omitted when empty.");
    }
    item["tags"].forEach((tag, i) => {
      if (typeof tag !== "string") {
        ctx.report("error", "CXF2002", `${path}.tags[${i}]`, `Tags must be strings, got ${kindOf(tag)}.`);
      }
    });
  }

  if (Array.isArray(item["credentials"])) {
    item["credentials"].forEach((cred, i) => {
      validateCredential(ctx, cred, `${path}.credentials[${i}]`, accountId, refs);
    });
  }

  vExtensions(ctx, item["extensions"], `${path}.extensions`, "Item");
}

function vScope(ctx: Ctx, scope: Json, path: string): void {
  checkMembers(ctx, scope, path, "CredentialScope", {
    urls: { kind: "array", required: true },
    androidApps: { kind: "array", required: true },
  });
  if (Array.isArray(scope["urls"])) {
    scope["urls"].forEach((url, i) => {
      if (typeof url !== "string") {
        ctx.report("error", "CXF2002", `${path}.urls[${i}]`, `URLs must be strings, got ${kindOf(url)}.`);
      }
    });
  }
  if (Array.isArray(scope["androidApps"])) {
    scope["androidApps"].forEach((app, i) => {
      const appPath = `${path}.androidApps[${i}]`;
      if (!isObj(app)) {
        ctx.report("error", "CXF2002", appPath, `AndroidAppIds must be objects, got ${kindOf(app)}.`);
        return;
      }
      checkMembers(ctx, app, appPath, "AndroidAppId", {
        bundleId: { kind: "string", required: true },
        certificate: { kind: "object" },
        name: { kind: "string" },
      });
      if (isObj(app["certificate"])) {
        const cert = app["certificate"];
        const certPath = `${appPath}.certificate`;
        checkMembers(ctx, cert, certPath, "AndroidAppCertificateFingerprint", {
          fingerprint: { kind: "string", required: true },
          hashAlg: { kind: "string", required: true },
        });
        vB64url(ctx, cert["fingerprint"], `${certPath}.fingerprint`);
        vEnum(ctx, cert["hashAlg"], `${certPath}.hashAlg`, HASH_ALGS, {
          requiredMember: true,
          structure: "certificate fingerprint",
        });
      }
    });
  }
}

// ---------------------------------------------------------------------------
// EditableField and extensions
// ---------------------------------------------------------------------------

const VALUE_FORMATS: Partial<
  Record<FieldType, { re: RegExp; severity: Severity; expectation: string }>
> = {
  "date": { re: /^\d{4}-\d{2}-\d{2}$/, severity: "error", expectation: "an RFC 3339 full-date (YYYY-MM-DD)" },
  "year-month": { re: /^\d{4}-\d{2}$/, severity: "error", expectation: "an RFC 3339 year-month (YYYY-MM)" },
  "boolean": { re: /^(true|false)$/, severity: "error", expectation: '"true" or "false"' },
  "number": { re: /^-?\d+(\.\d+)?$/, severity: "error", expectation: "a stringified number" },
  "country-code": { re: /^[A-Za-z]{2}$/, severity: "error", expectation: "an ISO 3166-1 alpha-2 code" },
  // Warnings only: the spec's own example uses bare "CA" and loose emails.
  "subdivision-code": { re: /^[A-Za-z]{2}-[A-Za-z0-9]{1,3}$/, severity: "warning", expectation: 'an ISO 3166-2 code like "US-CA"' },
  "email": { re: /^[^\s@]+@[^\s@]+$/, severity: "warning", expectation: "an email address" },
};

function vEditableField(
  ctx: Ctx,
  field: unknown,
  path: string,
  expected: readonly FieldType[] | undefined,
): void {
  if (field === undefined) return;
  if (!isObj(field)) {
    ctx.report("error", "CXF2002", path, `EditableFields must be objects, got ${kindOf(field)}.`);
    return;
  }
  checkMembers(ctx, field, path, "EditableField", {
    id: { kind: "string" },
    fieldType: { kind: "string", required: true },
    value: { kind: "string", required: true },
    label: { kind: "string" },
    extensions: { kind: "array" },
  });
  if ("id" in field) vB64url(ctx, field["id"], `${path}.id`, { id: true });
  vExtensions(ctx, field["extensions"], `${path}.extensions`, "EditableField", { nonEmpty: true });

  const fieldType = field["fieldType"];
  if (typeof fieldType !== "string") return;

  if (!isKnownFieldType(fieldType)) {
    ctx.report(
      "warning",
      "CXF2004",
      `${path}.fieldType`,
      `"${fieldType}" is not a known FieldType; importers treat this member as absent.`,
    );
    return;
  }
  if (expected !== undefined && !expected.includes(fieldType)) {
    ctx.report(
      "warning",
      "CXF2021",
      `${path}.fieldType`,
      `The spec prescribes fieldType ${expected.map((e) => `"${e}"`).join(" or ")} here, got "${fieldType}".`,
    );
  }

  const value = field["value"];
  if (typeof value !== "string") return;
  if (fieldType === "wifi-network-security-type") {
    vEnum(ctx, value, `${path}.value`, WIFI_NETWORK_SECURITY_TYPES, {
      requiredMember: false,
      structure: "field",
    });
    return;
  }
  const format = VALUE_FORMATS[fieldType];
  if (format && !format.re.test(value)) {
    ctx.report(
      format.severity,
      "CXF2008",
      `${path}.value`,
      `A "${fieldType}" value must be ${format.expectation}, got "${truncate(value)}".`,
    );
  }
}

function vExtensions(
  ctx: Ctx,
  extensions: unknown,
  path: string,
  owner: string,
  opts: { nonEmpty?: boolean } = {},
): void {
  if (!Array.isArray(extensions)) return;
  if (extensions.length === 0) {
    const detail = opts.nonEmpty
      ? "the CDDL requires this array to be non-empty when present"
      : "optional arrays should be omitted when empty";
    ctx.report("warning", "CXF2009", path, `${owner} has an empty extensions array; ${detail}.`);
    return;
  }
  extensions.forEach((ext, i) => {
    const extPath = `${path}[${i}]`;
    if (!isObj(ext)) {
      ctx.report("error", "CXF2002", extPath, `Extensions must be objects, got ${kindOf(ext)}.`);
      return;
    }
    if (typeof ext["name"] !== "string") {
      ctx.report("error", "CXF2001", extPath, 'Extensions must carry a string "name" member.');
      return;
    }
    if (ext["name"] === "shared") {
      vShared(ctx, ext, extPath);
    } else if (!ext["name"].includes("/")) {
      ctx.report(
        "warning",
        "CXF2012",
        `${extPath}.name`,
        `"${ext["name"]}" is not a registered extension; custom names must use the "EXPORTER_RP_ID/EXTENSION_NAME" form.`,
      );
    }
  });
}

function vShared(ctx: Ctx, ext: Json, path: string): void {
  if (!Array.isArray(ext["accessors"])) {
    ctx.report("error", "CXF2001", path, 'The "shared" extension requires an "accessors" array.');
    return;
  }
  ext["accessors"].forEach((acc, i) => {
    const accPath = `${path}.accessors[${i}]`;
    if (!isObj(acc)) {
      ctx.report("error", "CXF2002", accPath, `SharingAccessors must be objects, got ${kindOf(acc)}.`);
      return;
    }
    checkMembers(ctx, acc, accPath, "SharingAccessor", {
      type: { kind: "string", required: true },
      accountId: { kind: "string", required: true },
      name: { kind: "string", required: true },
      permissions: { kind: "array", required: true },
    });
    vB64url(ctx, acc["accountId"], `${accPath}.accountId`);
    if (typeof acc["type"] === "string" && !(SHARING_ACCESSOR_TYPES as readonly string[]).includes(acc["type"])) {
      ctx.report(
        "warning",
        "CXF2013",
        `${accPath}.type`,
        `"${acc["type"]}" is not a known accessor type (user, group); importers must ignore this accessor.`,
      );
    }
    if (Array.isArray(acc["permissions"])) {
      if (acc["permissions"].length === 0) {
        ctx.report(
          "warning",
          "CXF2013",
          `${accPath}.permissions`,
          "Accessors with an empty permissions list are ignored by importers.",
        );
      }
      acc["permissions"].forEach((perm, j) => {
        if (typeof perm !== "string") {
          ctx.report("error", "CXF2002", `${accPath}.permissions[${j}]`, `Permissions must be strings, got ${kindOf(perm)}.`);
        } else if (!(SHARING_ACCESSOR_PERMISSIONS as readonly string[]).includes(perm)) {
          ctx.report(
            "warning",
            "CXF2013",
            `${accPath}.permissions[${j}]`,
            `"${perm}" is not a known permission (${SHARING_ACCESSOR_PERMISSIONS.join(", ")}); importers must ignore it.`,
          );
        }
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/** Prescribed EditableField member -> fieldType for the field-bag credentials. */
const EF_CREDENTIALS: Record<string, Record<string, FieldType>> = {
  "address": {
    streetAddress: "string", postalCode: "string", city: "string",
    territory: "subdivision-code", country: "country-code", tel: "string",
  },
  "api-key": {
    key: "concealed-string", username: "string", keyType: "string",
    url: "string", validFrom: "date", expiryDate: "date",
  },
  "basic-auth": { username: "string", password: "concealed-string" },
  "credit-card": {
    number: "concealed-string", fullName: "string", cardType: "string",
    verificationNumber: "concealed-string", pin: "concealed-string",
    expiryDate: "year-month", validFrom: "year-month",
  },
  "drivers-license": {
    fullName: "string", birthDate: "date", issueDate: "date", expiryDate: "date",
    issuingAuthority: "string", territory: "subdivision-code", country: "country-code",
    licenseNumber: "string", licenseClass: "string",
  },
  "identity-document": {
    issuingCountry: "country-code", documentNumber: "string", identificationNumber: "string",
    nationality: "string", fullName: "string", birthDate: "date", birthPlace: "string",
    sex: "string", issueDate: "date", expiryDate: "date", issuingAuthority: "string",
  },
  "passport": {
    issuingCountry: "country-code", passportType: "string", passportNumber: "string",
    nationalIdentificationNumber: "string", nationality: "string", fullName: "string",
    birthDate: "date", birthPlace: "string", sex: "string", issueDate: "date",
    expiryDate: "date", issuingAuthority: "string",
  },
  "person-name": {
    title: "string", given: "string", givenInformal: "string", given2: "string",
    surnamePrefix: "string", surname: "string", surname2: "string",
    credentials: "string", generation: "string",
  },
};

const BASE32_RE = /^[A-Z2-7]+=*$/i;

function validateCredential(
  ctx: Ctx,
  cred: unknown,
  path: string,
  accountId: string | undefined,
  refs: Map<string, Set<string>>,
): void {
  if (!isObj(cred)) {
    ctx.report("error", "CXF2002", path, `Credentials must be objects, got ${kindOf(cred)}.`);
    return;
  }
  const type = cred["type"];
  if (typeof type !== "string") {
    ctx.report("error", "CXF2001", path, 'Credentials must carry a string "type" member.');
    return;
  }
  if (!isKnownCredentialType(type)) {
    ctx.report(
      "warning",
      "CXF2004",
      `${path}.type`,
      `"${type}" is not a known credential type; importers must ignore this credential (its content is preserved, not checked).`,
    );
    return;
  }

  const efSpec = EF_CREDENTIALS[type];
  if (efSpec !== undefined) {
    const rules: Record<string, MemberRule> = { type: { kind: "string", required: true } };
    for (const name of Object.keys(efSpec)) rules[name] = { kind: "object" };
    checkMembers(ctx, cred, path, `"${type}" credential`, rules);
    for (const [name, fieldType] of Object.entries(efSpec)) {
      if (name in cred) vEditableField(ctx, cred[name], `${path}.${name}`, [fieldType]);
    }
    return;
  }

  switch (type) {
    case "custom-fields": {
      checkMembers(ctx, cred, path, '"custom-fields" credential', {
        type: { kind: "string", required: true },
        id: { kind: "string" },
        label: { kind: "string" },
        fields: { kind: "array", required: true },
        extensions: { kind: "array" },
      });
      if ("id" in cred) vB64url(ctx, cred["id"], `${path}.id`, { id: true });
      if (Array.isArray(cred["fields"])) {
        cred["fields"].forEach((f, i) => vEditableField(ctx, f, `${path}.fields[${i}]`, undefined));
      }
      vExtensions(ctx, cred["extensions"], `${path}.extensions`, "CustomFields", { nonEmpty: true });
      return;
    }
    case "file": {
      checkMembers(ctx, cred, path, '"file" credential', {
        type: { kind: "string", required: true },
        id: { kind: "string", required: true },
        name: { kind: "string", required: true },
        decryptedSize: { kind: "number", required: true },
        integrityHash: { kind: "string", required: true },
      });
      vB64url(ctx, cred["id"], `${path}.id`, { id: true });
      vB64url(ctx, cred["integrityHash"], `${path}.integrityHash`);
      vUint(ctx, cred["decryptedSize"], `${path}.decryptedSize`, Number.MAX_SAFE_INTEGER, "decryptedSize");
      vFilePayload(ctx, cred, path);
      return;
    }
    case "generated-password": {
      checkMembers(ctx, cred, path, '"generated-password" credential', {
        type: { kind: "string", required: true },
        password: { kind: "string", required: true },
      });
      return;
    }
    case "item-reference": {
      checkMembers(ctx, cred, path, '"item-reference" credential', {
        type: { kind: "string", required: true },
        reference: { kind: "object", required: true },
      });
      if (isObj(cred["reference"])) {
        vLinkedItem(ctx, cred["reference"], `${path}.reference`, accountId, refs);
      }
      return;
    }
    case "note": {
      checkMembers(ctx, cred, path, '"note" credential', {
        type: { kind: "string", required: true },
        content: { kind: "object", required: true },
      });
      vEditableField(ctx, cred["content"], `${path}.content`, ["string"]);
      return;
    }
    case "passkey":
      vPasskey(ctx, cred, path);
      return;
    case "ssh-key": {
      checkMembers(ctx, cred, path, '"ssh-key" credential', {
        type: { kind: "string", required: true },
        keyType: { kind: "string", required: true },
        privateKey: { kind: "string", required: true },
        keyComment: { kind: "string" },
        creationDate: { kind: "object" },
        expiryDate: { kind: "object" },
        keyGenerationSource: { kind: "object" },
      });
      if (vB64url(ctx, cred["privateKey"], `${path}.privateKey`)) {
        vPkcs8(ctx, cred["privateKey"] as string, `${path}.privateKey`);
      }
      if ("creationDate" in cred) vEditableField(ctx, cred["creationDate"], `${path}.creationDate`, ["date"]);
      if ("expiryDate" in cred) vEditableField(ctx, cred["expiryDate"], `${path}.expiryDate`, ["date"]);
      if ("keyGenerationSource" in cred) {
        vEditableField(ctx, cred["keyGenerationSource"], `${path}.keyGenerationSource`, ["string"]);
      }
      return;
    }
    case "totp":
      vTotp(ctx, cred, path);
      return;
    case "wifi": {
      checkMembers(ctx, cred, path, '"wifi" credential', {
        type: { kind: "string", required: true },
        ssid: { kind: "object" },
        networkSecurityType: { kind: "object" },
        passphrase: { kind: "object" },
        hidden: { kind: "object" },
      });
      if ("ssid" in cred) vEditableField(ctx, cred["ssid"], `${path}.ssid`, ["string"]);
      if ("networkSecurityType" in cred) {
        vEditableField(ctx, cred["networkSecurityType"], `${path}.networkSecurityType`, [
          "wifi-network-security-type",
          "string",
        ]);
      }
      if ("passphrase" in cred) vEditableField(ctx, cred["passphrase"], `${path}.passphrase`, ["concealed-string"]);
      if ("hidden" in cred) vEditableField(ctx, cred["hidden"], `${path}.hidden`, ["boolean"]);
      return;
    }
  }
}

function vPasskey(ctx: Ctx, cred: Json, path: string): void {
  checkMembers(ctx, cred, path, '"passkey" credential', {
    type: { kind: "string", required: true },
    credentialId: { kind: "string", required: true },
    rpId: { kind: "string", required: true },
    username: { kind: "string", required: true },
    userDisplayName: { kind: "string", required: true },
    userHandle: { kind: "string", required: true },
    key: { kind: "string", required: true },
    fido2Extensions: { kind: "object" },
  });
  vB64url(ctx, cred["credentialId"], `${path}.credentialId`);
  vB64url(ctx, cred["userHandle"], `${path}.userHandle`);
  if (vB64url(ctx, cred["key"], `${path}.key`)) {
    vPkcs8(ctx, cred["key"] as string, `${path}.key`);
  }

  const f2e = cred["fido2Extensions"];
  if (!isObj(f2e)) return;
  const f2ePath = `${path}.fido2Extensions`;
  checkMembers(ctx, f2e, f2ePath, "Fido2Extensions", {
    hmacCredentials: { kind: "object" },
    credBlob: { kind: "string" },
    largeBlob: { kind: "object" },
    payments: { kind: "boolean" },
  });
  if (isObj(f2e["hmacCredentials"])) {
    const hmac = f2e["hmacCredentials"];
    const hmacPath = `${f2ePath}.hmacCredentials`;
    checkMembers(ctx, hmac, hmacPath, "Fido2HmacCredentials", {
      algorithm: { kind: "string", required: true },
      credWithUV: { kind: "string", required: true },
      credWithoutUV: { kind: "string", required: true },
    });
    vEnum(ctx, hmac["algorithm"], `${hmacPath}.algorithm`, FIDO2_HMAC_CREDENTIAL_ALGORITHMS, {
      requiredMember: true,
      structure: "hmac credentials structure",
    });
    vB64url(ctx, hmac["credWithUV"], `${hmacPath}.credWithUV`);
    vB64url(ctx, hmac["credWithoutUV"], `${hmacPath}.credWithoutUV`);
  }
  if ("credBlob" in f2e) vB64url(ctx, f2e["credBlob"], `${f2ePath}.credBlob`);
  if (isObj(f2e["largeBlob"])) {
    const blob = f2e["largeBlob"];
    const blobPath = `${f2ePath}.largeBlob`;
    checkMembers(ctx, blob, blobPath, "Fido2LargeBlob", {
      uncompressedSize: { kind: "number", required: true },
      data: { kind: "string", required: true },
    });
    vUint(ctx, blob["uncompressedSize"], `${blobPath}.uncompressedSize`, Number.MAX_SAFE_INTEGER, "uncompressedSize");
    vB64url(ctx, blob["data"], `${blobPath}.data`);
  }
}

function vTotp(ctx: Ctx, cred: Json, path: string): void {
  // period/digits/algorithm are required by the CDDL but have documented
  // importer defaults, so their absence is a warning (SPEC_NOTES #8);
  // secret has no default and its absence makes the credential unusable.
  checkMembers(ctx, cred, path, '"totp" credential', {
    type: { kind: "string", required: true },
    secret: { kind: "string", required: true },
    period: { kind: "number" },
    digits: { kind: "number" },
    username: { kind: "string" },
    algorithm: { kind: "string" },
    issuer: { kind: "string" },
  });
  for (const [name, fallback] of [["period", "30 seconds"], ["digits", "6"], ["algorithm", '"sha1"']] as const) {
    if (!(name in cred)) {
      ctx.report(
        "warning",
        "CXF2014",
        `${path}.${name}`,
        `TOTP "${name}" is required by the CDDL; importers fall back to ${fallback} when it is absent.`,
      );
    }
  }
  if (typeof cred["secret"] === "string" && !BASE32_RE.test(cred["secret"])) {
    ctx.report(
      "error",
      "CXF2008",
      `${path}.secret`,
      "TOTP secrets must be base32 (RFC 4648 §6: A-Z, 2-7).",
    );
  }
  vUint(ctx, cred["period"], `${path}.period`, 65535, "period");
  vUint(ctx, cred["digits"], `${path}.digits`, 65535, "digits");
  if ("algorithm" in cred) {
    vEnum(ctx, cred["algorithm"], `${path}.algorithm`, OTP_HASH_ALGORITHMS, {
      requiredMember: true,
      structure: "TOTP credential",
    });
  }
}

function vPkcs8(ctx: Ctx, b64: string, path: string): void {
  if (b64.length === 0) return;
  const bytes = Buffer.from(b64, "base64url");
  if (bytes.length === 0 || bytes[0] !== 0x30) {
    ctx.report(
      "warning",
      "CXF2019",
      path,
      "Key does not start with a DER SEQUENCE (0x30); the spec requires PKCS#8 DER encoding.",
    );
  }
}

function vFilePayload(ctx: Ctx, cred: Json, path: string): void {
  if (ctx.options.source !== "archive" || ctx.options.files === undefined) return;
  const id = cred["id"];
  if (typeof id !== "string") return;
  const payload = ctx.options.files.get(id);
  if (payload === undefined) {
    ctx.report(
      "warning",
      "CXF2017",
      `${path}.id`,
      `No "documents/${id}" entry in the archive for this file credential.`,
    );
    return;
  }
  if (typeof cred["decryptedSize"] === "number" && payload.byteLength !== cred["decryptedSize"]) {
    ctx.report(
      "error",
      "CXF2016",
      `${path}.decryptedSize`,
      `Archive payload is ${payload.byteLength} bytes but the credential declares ${cred["decryptedSize"]}.`,
    );
  }
  if (typeof cred["integrityHash"] === "string" && B64URL_RE.test(cred["integrityHash"])) {
    const actual = createHash("sha256").update(payload).digest("base64url");
    if (actual !== cred["integrityHash"]) {
      ctx.report(
        "error",
        "CXF2016",
        `${path}.integrityHash`,
        `Archive payload SHA-256 is ${actual}, which does not match the declared integrityHash.`,
      );
    }
  }
}
