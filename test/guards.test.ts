import { describe, expect, it } from "vitest";
import {
  credentialOfType,
  isKnownCredential,
  isSharedExtension,
  isUnknownCredential,
} from "../src/guards.js";
import type { Credential, Extension, Passkey } from "../src/types.js";

const passkey: Passkey = {
  type: "passkey",
  credentialId: "cred-id",
  rpId: "example.com",
  username: "yusuf",
  userDisplayName: "Yusuf",
  userHandle: "handle",
  key: "cGtjczg",
};

const vendorSpecific: Credential = {
  type: "provider.example/loyalty-card",
  memberNumber: "12345",
};

describe("credential guards", () => {
  it("separates known from unknown credentials", () => {
    expect(isKnownCredential(passkey)).toBe(true);
    expect(isUnknownCredential(passkey)).toBe(false);
    expect(isKnownCredential(vendorSpecific)).toBe(false);
    expect(isUnknownCredential(vendorSpecific)).toBe(true);
  });

  it("narrows a Credential to a concrete type in one step", () => {
    const c: Credential = passkey;
    expect(credentialOfType(c, "passkey")).toBe(true);
    if (credentialOfType(c, "passkey")) {
      // Type-level check: rpId is only reachable after narrowing to Passkey.
      expect(c.rpId).toBe("example.com");
    }
    expect(credentialOfType(c, "totp")).toBe(false);
    expect(credentialOfType(vendorSpecific, "passkey")).toBe(false);
  });
});

describe("extension guards", () => {
  it("accepts a well-formed shared extension", () => {
    const shared: Extension = {
      name: "shared",
      accessors: [
        { type: "user", accountId: "abc", name: "yusuf", permissions: ["read"] },
      ],
    };
    expect(isSharedExtension(shared)).toBe(true);
    if (isSharedExtension(shared)) {
      expect(shared.accessors[0]?.permissions).toContain("read");
    }
  });

  it("does not trust the name alone", () => {
    const malformed: Extension = { name: "shared" };
    expect(isSharedExtension(malformed)).toBe(false);
    const custom: Extension = { name: "provider.example/VaultType", vault: "work" };
    expect(isSharedExtension(custom)).toBe(false);
  });
});
