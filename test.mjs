#!/usr/bin/env node
/* Smoke test for ffraud-mcp: both faces, against the live public API.
 *
 * It asserts the PROTOCOL and the SHAPE, never a specific score: an IP's
 * fraud score moves as the database learns, so asserting 75 would make this
 * test fail for the wrong reason on a Tuesday.
 *
 *   node test.mjs
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(HERE, "index.mjs");

let failed = 0;
const check = (name, cond, detail = "") => {
  if (cond) {
    console.log(`  ok   ${name}`);
  } else {
    console.error(`  FAIL ${name}${detail ? ` — ${detail}` : ""}`);
    failed++;
  }
};

/* ---- the MCP face: drive it over stdio the way a client would ---- */

function rpc(requests) {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, [ENTRY], { stdio: ["pipe", "pipe", "ignore"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.on("error", reject);
    p.on("close", () =>
      resolve(
        out
          .trim()
          .split("\n")
          .filter(Boolean)
          .map((l) => JSON.parse(l)),
      ),
    );
    for (const r of requests) p.stdin.write(JSON.stringify(r) + "\n");
    p.stdin.end();
    setTimeout(() => p.kill(), 60000).unref();
  });
}

console.log("MCP face");
const msgs = await rpc([
  { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "domain_check", arguments: { domain: "mailinator.com" } } },
  { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "nope", arguments: {} } },
]);

const byId = Object.fromEntries(msgs.map((m) => [m.id, m]));

check("initialize returns serverInfo", byId[1]?.result?.serverInfo?.name === "ffraud");
check("initialize declares tools capability", !!byId[1]?.result?.capabilities?.tools);
const names = (byId[2]?.result?.tools ?? []).map((t) => t.name).sort();
check(
  "tools/list returns all five",
  JSON.stringify(names) === JSON.stringify(["domain_check", "email_check", "ip_check", "ip_reports", "site_check"]),
  names.join(","),
);
check(
  "every tool carries a description and a schema",
  (byId[2]?.result?.tools ?? []).every((t) => t.description?.length > 20 && t.inputSchema?.type === "object"),
);
const called = byId[3]?.result?.content?.[0]?.text;
check("tools/call returns text content", typeof called === "string" && called.length > 10);
check("a known disposable domain is reported as one", called ? JSON.parse(called).is_disposable === true : false);
/* An unknown tool is a PROTOCOL error, unlike a tool that ran and failed. */
check("an unknown tool is a JSON-RPC error", byId[4]?.error?.code === -32602);

/* ---- the CLI face ---- */

function cli(args) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [ENTRY, ...args], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.on("close", (code) => resolve({ code, out }));
    setTimeout(() => p.kill(), 60000).unref();
  });
}

console.log("CLI face");
const ip = await cli(["ip", "8.8.8.8"]);
let ipJson = null;
try {
  ipJson = JSON.parse(ip.out);
} catch {}
check("ffraud ip exits 0", ip.code === 0, `exit ${ip.code}`);
check("ffraud ip prints JSON for the address asked", ipJson?.ip === "8.8.8.8");
check("the score is a number in range", typeof ipJson?.fraud_score === "number" && ipJson.fraud_score >= 0 && ipJson.fraud_score <= 100);
check("the risk band is one of the documented values", ["none", "low", "medium", "high", "critical"].includes(ipJson?.risk));

const email = await cli(["email", "test@mailinator.com"]);
let emailJson = null;
try {
  emailJson = JSON.parse(email.out);
} catch {}
check("ffraud email exits 0", email.code === 0);
check("a throwaway mailbox is flagged disposable", emailJson?.is_disposable === true);

/* The website check: one real site, the shape only (a site's grade moves as its owner changes headers). */
const site = await cli(["site", "https://example.com/some/page"]);
let siteJson = null;
try {
  siteJson = JSON.parse(site.out);
} catch {}
check("ffraud site exits 0", site.code === 0, `exit ${site.code}`);
check("ffraud site checks the host of a URL", siteJson?.host === "example.com");
check("the site score is a number in range", typeof siteJson?.score === "number" && siteJson.score >= 0 && siteJson.score <= 100);
check("the grade is one of A to F", ["A", "B", "C", "D", "F"].includes(siteJson?.grade));
check("every finding carries its fix", Array.isArray(siteJson?.findings) && siteJson.findings.every((f) => typeof f.fix === "string" && f.fix.length > 0));

const help = await cli(["--help"]);
check("--help prints usage", help.out.includes("ffraud"));

const bad = await cli(["nonsense"]);
check("an unknown command exits non-zero", bad.code !== 0, `exit ${bad.code}`);

console.log(failed ? `\n${failed} check(s) failed` : "\nall checks passed");
process.exit(failed ? 1 : 0);
