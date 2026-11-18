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
    for (const r of requests) p.stdin.write((typeof r === "string" ? r : JSON.stringify(r)) + "\n");
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
  { jsonrpc: "2.0", id: 5, method: "initialize", params: { protocolVersion: "2099-01-01" } },
  "this line is not JSON",
]);

const byId = Object.fromEntries(msgs.filter((m) => m.id !== null).map((m) => [m.id, m]));
check("a version the server speaks comes back as asked", byId[1]?.result?.protocolVersion === "2024-11-05");
check("a version it does not speak gets its newest instead of an echo", byId[5]?.result?.protocolVersion === "2025-11-25", byId[5]?.result?.protocolVersion);
check("a line that is not JSON gets a parse error", msgs.some((m) => m.id === null && m.error?.code === -32700));

check("initialize returns serverInfo", byId[1]?.result?.serverInfo?.name === "ffraud");
check("initialize declares tools capability", !!byId[1]?.result?.capabilities?.tools);
const names = (byId[2]?.result?.tools ?? []).map((t) => t.name).sort();
check(
  "tools/list returns all seven",
  JSON.stringify(names) === JSON.stringify(["claim_api_key", "domain_check", "email_check", "ip_check", "ip_reports", "request_api_key", "site_check"]),
  names.join(","),
);
const acting = (byId[2]?.result?.tools ?? []).filter((t) => t.annotations?.readOnlyHint === false).map((t) => t.name).sort();
check("only the two key tools say they act; every check reads only", JSON.stringify(acting) === JSON.stringify(["claim_api_key", "request_api_key"]), acting.join(","));
check(
  "every tool carries a description and a schema",
  (byId[2]?.result?.tools ?? []).every((t) => t.description?.length > 20 && t.inputSchema?.type === "object"),
);
const called = byId[3]?.result?.content?.[0]?.text;
check("tools/call returns text content", typeof called === "string" && called.length > 10);
check("the answer is compact JSON (the model pays for every character)", typeof called === "string" && !called.includes("\n"));
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
check("--help prints usage", help.out.includes("ffraud") && help.out.includes("ffraud setup"));

const all = await cli(["setup"]);
check("setup prints every app's line", all.code === 0 && all.out.includes("claude mcp add --transport http ffraud https://ffraud.com/api/mcp") && all.out.includes("codex mcp add ffraud --url"));
check("setup adds the local lines", all.out.includes("claude mcp add ffraud -- npx -y ffraud mcp") && all.out.includes("npx ffraud doctor"));
const one = await cli(["setup", "cursor"]);
check("setup cursor prints Cursor alone", one.code === 0 && one.out.includes("~/.cursor/mcp.json") && !one.out.includes("Claude Code"));
const asJson = await cli(["setup", "--json", "vscode"]);
let setupJson = null;
try {
  setupJson = JSON.parse(asJson.out);
} catch {}
check("setup --json is JSON a program can read", setupJson?.apps?.length === 1 && setupJson.apps[0].name === "VS Code" && setupJson.hosted?.url === "https://ffraud.com/api/mcp");
const typo = await cli(["setup", "notepad"]);
check("an app setup does not know exits 1", typo.code === 1);
const doc = await cli(["doctor"]);
check("doctor passes from this machine", doc.code === 0 && doc.out.includes("Everything works"), doc.out);

const bad = await cli(["nonsense"]);
check("an unknown command exits non-zero", bad.code !== 0, `exit ${bad.code}`);

console.log(failed ? `\n${failed} check(s) failed` : "\nall checks passed");
process.exit(failed ? 1 : 0);
