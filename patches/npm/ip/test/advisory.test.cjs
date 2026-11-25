// Regression tests for GHSA-2p57-rm9w-gvfp (CVE-2024-29415) in the `ip` package.
// Run against a built patch: FOSTER_TARGET=/path/to/package node --test test/
const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const target = process.env.FOSTER_TARGET;
if (!target) throw new Error("set FOSTER_TARGET to the directory of the patched package");
const ip = require(path.resolve(target));

// The examples listed in the advisory itself. All are private or loopback addresses.
const ADVISORY_EXAMPLES = ["127.1", "01200034567", "012.1.2.3", "000:0:0000::01", "::fFFf:127.0.0.1"];

test("advisory examples are no longer reported as public", () => {
  for (const addr of ADVISORY_EXAMPLES) {
    assert.equal(ip.isPublic(addr), false, `${addr} must not be public`);
    assert.equal(ip.isPrivate(addr), true, `${addr} must be private`);
  }
});

// CVE-2025-59436 (indutny/node-ip#160): a bare octal number for 127.0.0.1.
test("CVE-2025-59436: 017700000001 is loopback, not public", () => {
  assert.equal(ip.isPublic("017700000001"), false);
  assert.equal(ip.isLoopback("017700000001"), true);
});

// indutny/node-ip#170: isV6Format() matched octal dotted quads, skipping IPv4 normalisation.
test("node-ip#170: octal dotted quads in 10/8 and 172.16/12 are private", () => {
  for (const addr of ["012.0.0.1", "012.100.200.3", "0254.020.0.1", "0254.021.0.1", "0254.036.0.1", "0254.037.0.1"]) {
    assert.equal(ip.isPrivate(addr), true, `${addr} must be private`);
  }
});

test("other spellings of loopback and private addresses are caught", () => {
  const sneaky = [
    "0x7f.1",
    "0x7f000001",
    "2130706433",
    "0177.0.0.1",
    "127.0.0.1",
    "0:0:0:0:0:ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::FFFF:10.0.0.1",
    "64:ff9b::127.0.0.1", // NAT64
    "::127.0.0.1", // IPv4-compatible
    "0.0.0.0",
    "0",
    "169.254.169.254", // cloud metadata endpoint
    "0xa9.0xfe.0xa9.0xfe",
    "fe80::1%eth0",
  ];
  for (const addr of sneaky) assert.equal(ip.isPublic(addr), false, `${addr} must not be public`);
});

test("private ranges stay private", () => {
  const priv = ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.0.1", "fc00::1", "fd12:3456::1", "fe80::abcd", "febf::1", "::1", "::"];
  for (const addr of priv) assert.equal(ip.isPrivate(addr), true, `${addr} must be private`);
});

test("public addresses stay public", () => {
  const pub = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "192.169.0.1", "11.0.0.1", "100.64.0.1", "2001:4860:4860::8888", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "fec0::1"];
  for (const addr of pub) assert.equal(ip.isPublic(addr), true, `${addr} must be public`);
});

test("isLoopback recognises every spelling of 127/8 and ::1", () => {
  for (const addr of ["127.0.0.1", "127.1", "127.255.255.254", "2130706433", "0x7f.1", "0177.1", "::1", "000:0:0000::01", "::fFFf:127.0.0.1", "fe80::1"]) {
    assert.equal(ip.isLoopback(addr), true, `${addr} is loopback`);
  }
  for (const addr of ["10.0.0.1", "8.8.8.8", "::2", "fe80::2", "localhost", ""]) {
    assert.equal(ip.isLoopback(addr), false, `${addr} is not loopback`);
  }
});

test("IPv4 parsing agrees with the WHATWG URL parser used by fetch()", () => {
  const forms = ["127.1", "012.1.2.3", "01200034567", "0x7f.0.0.1", "2130706433", "0xC0.0xA8.1.1", "3232235777", "1.2.3.4", "0300.0250.0.1"];
  for (const addr of forms) {
    const host = new URL(`http://${addr}/`).hostname;
    assert.equal(ip.isPrivate(addr), ip.isPrivate(host), `${addr} (${host}) classified differently from its canonical form`);
  }
});

test("invalid input still throws from isPrivate, like the original", () => {
  for (const bad of ["not-an-ip", "1.2.3.256", "1.2.3.4.5", "1..2.3"]) {
    assert.throws(() => ip.isPrivate(bad), `${bad} should throw`);
  }
});
