/**
 * Exit-code contract tests. These spawn the BUILT dist/cli.js as a real child
 * process — the in-process suites can't catch a broken `process.exitCode`
 * wiring (and didn't: main()'s return value was once discarded entirely).
 *
 * Contract: 0 conforming (warnings allowed), 1 validation errors, 2 unusable
 * input or usage error.
 */

import { execSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(ROOT, "dist", "cli.js");
const FIXTURES = join(ROOT, "test", "fixtures");

let tmp: string;

beforeAll(() => {
  execSync("npm run build", { cwd: ROOT, stdio: "pipe" });
  tmp = mkdtempSync(join(tmpdir(), "cxf-cli-"));
}, 60_000);

afterAll(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function run(...args: string[]): { status: number | null; stdout: string; stderr: string } {
  const res = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

function tmpFile(name: string, content: string): string {
  const path = join(tmp, name);
  writeFileSync(path, content, "utf8");
  return path;
}

describe("exit code 0: conforming documents", () => {
  it("validate on a conforming document with warnings exits 0", () => {
    const res = run("validate", join(FIXTURES, "synthetic", "kitchen-sink.json"));
    expect(res.status).toBe(0);
    expect(res.stdout).toContain("0 error(s)");
    expect(res.stdout).toContain("OK: document conforms");
  });

  it("inspect on a conforming document exits 0", () => {
    const res = run("inspect", join(FIXTURES, "spec", "appendix-a.json"));
    expect(res.status).toBe(0);
    expect(res.stdout).toContain("Accounts:  1");
  });

  it("--help exits 0", () => {
    expect(run("--help").status).toBe(0);
  });
});

describe("inspect allowlist and --redact", () => {
  const kitchen = join(FIXTURES, "synthetic", "kitchen-sink.json");
  const SECRETS = [
    "hunter2", // basic-auth password (concealed-string)
    "JBSWY3DPEHPK3PXP", // totp secret
    "correct horse battery staple", // generated password
    "sk-live-123", // api-key key (concealed-string)
    "4111111111111111", // credit-card number
    "difference-engine", // wifi passphrase
    "cGtjczgtZGVyLWJ5dGVz", // passkey private key
    "cGtjczgtc3NoLWtleQ", // ssh private key
    "GEZDGNBVGY3TQOJQ", // custom-fields field value
    "1234567890", // unknown-credential string member
    "Y3JlZFdpdGhVVg", // fido2 hmac credential
  ];

  it("never prints credential value scalars, in any mode (allowlist, not denylist)", () => {
    for (const flags of [[], ["--redact"], ["--json"], ["--json", "--redact"]]) {
      const res = run("inspect", kitchen, ...flags);
      expect(res.status).toBe(0);
      const allOutput = res.stdout + res.stderr; // a leak on either stream is a leak
      for (const secret of SECRETS) {
        expect(allOutput, `flags=${flags.join(" ")} leaked ${secret}`).not.toContain(secret);
      }
    }
  });

  it("shows identity and structural metadata by default", () => {
    const out = run("inspect", kitchen).stdout;
    expect(out).toContain("username: ada"); // identity
    expect(out).toContain("Example Login"); // item title
    expect(out).toContain("rpId: webauthn.io"); // identity
    expect(out).toContain("period: 30"); // structural config
    expect(out).toContain("cxf-kit.example/loyalty-card"); // unknown type name, no content
  });

  it("--redact hides identity fields but keeps structure", () => {
    const out = run("inspect", kitchen, "--redact").stdout;
    expect(out).not.toContain("ada");
    expect(out).not.toContain("Example Login");
    expect(out).not.toContain("webauthn.io");
    expect(out).toContain("[redacted]");
    expect(out).toContain("basic-auth"); // types and counts survive
    expect(out).toContain("period: 30");
    expect(out).toContain("Items: 8");
  });

  it("the old --no-redact reveal flag no longer exists", () => {
    expect(run("inspect", kitchen, "--no-redact").status).toBe(2);
  });
});

describe("exit code 1: validation errors", () => {
  it("a parseable document with conformance errors exits 1", () => {
    const file = tmpFile("invalid.json", JSON.stringify({
      version: { major: 1, minor: 0 },
      exporterRpId: "test.example",
      exporterDisplayName: "test",
      timestamp: 1,
      accounts: [{ id: "dGVzdA", collections: [], items: [] }], // no username/email
    }));
    const res = run("validate", file);
    expect(res.status).toBe(1);
    expect(res.stdout).toContain("error CXF2001");
    expect(res.stdout).toContain("FAIL:");
  });

  it("--json mode reports the same failure with exit 1", () => {
    const file = tmpFile("invalid2.json", JSON.stringify({ accounts: [{}] }));
    const res = run("validate", file, "--json");
    expect(res.status).toBe(1);
    expect(JSON.parse(res.stdout).ok).toBe(false);
  });
});

describe("exit code 2: unusable input and usage errors", () => {
  it("malformed JSON exits 2 (CXF1001)", () => {
    const res = run("validate", tmpFile("broken.json", "{ not json"));
    expect(res.status).toBe(2);
    expect(res.stderr).toContain("CXF1001");
  });

  it("an empty file exits 2 (CXF1001)", () => {
    expect(run("validate", tmpFile("empty.json", "")).status).toBe(2);
  });

  it("a JSON object that is not a CXF header exits 2 (CXF1005)", () => {
    const res = run("validate", tmpFile("hello.json", '{"hello": 1}'));
    expect(res.status).toBe(2);
    expect(res.stderr).toContain("CXF1005");
  });

  it("inspect on unusable input exits 2 as well", () => {
    expect(run("inspect", tmpFile("broken2.json", "[]")).status).toBe(2);
  });

  it("a nonexistent file exits 2", () => {
    expect(run("validate", join(tmp, "no-such-file.json")).status).toBe(2);
  });

  it("missing command or file argument exits 2", () => {
    expect(run().status).toBe(2);
    expect(run("validate").status).toBe(2);
    expect(run("frobnicate", "x.json").status).toBe(2);
  });
});
