#!/usr/bin/env node
/* ============================================================
   FFRAUD: the open fraud database as tools an AI can call, and a CLI.

   FFraud publishes website, IP and email fraud intelligence that needs
   no key. An assistant can already curl it; this makes it first-class,
   so a model reaches for it without being handed a URL.

   Two faces, one file:

     MCP   npx ffraud mcp                speaks JSON-RPC 2.0 over stdio
                                         (stdout IS the protocol, so
                                         every log line goes to stderr)
     CLI   npx ffraud site example.com
           npx ffraud ip 8.8.8.8
           npx ffraud email throwaway@mailinator.com
           npx ffraud domain mailinator.com
           npx ffraud reports 45.33.32.156
           npx ffraud signup you@example.com  a key, by one approval email

   Zero dependencies on purpose: node 18+ has fetch, and an assistant
   that must install a tree before it can check an IP will not bother.

   Keys: every check here uses a PUBLIC endpoint and needs no key. If
   FFRAUD_API_KEY is set it is forwarded, which raises burst limits and
   site_check's hourly allowance (20 fresh checks per address, 300 per
   account) and nothing else. Two tools act, and say so: request_api_key
   has FFraud email the person one Approve button, and claim_api_key picks
   up the key once they pressed it (`ffraud signup` does both). Nothing is
   created without that click, and nothing here can spend money.
   ============================================================ */

const BASE = process.env.FFRAUD_BASE_URL ?? "https://api.ffraud.com";
const KEY = process.env.FFRAUD_API_KEY ?? "";
const VERSION = "1.2.0";
const UA = `ffraud/${VERSION} (+https://ffraud.com/docs/mcp)`;
/* FFraud's hosted MCP server (website/src/app/api/mcp/route.ts): the same tools with nothing to install. */
const HOSTED = process.env.FFRAUD_MCP_URL ?? "https://ffraud.com/api/mcp";
/* The protocol versions this server speaks, newest first. A client asking for one of them gets it back; a client
   asking for anything else gets the newest, as the protocol asks (until 1.1.1 any string came back unchecked). */
const PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

async function api(path, init) {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      accept: "application/json",
      "user-agent": UA,
      /* The engine reads a key from X-API-Key only (ffraud-engine/src/routes/api_key_auth.rs); a bearer
         token there is a dashboard session, so a key sent that way was never read and the batch call failed. */
      ...(KEY ? { "x-api-key": KEY } : {}),
      ...(init?.headers ?? {}),
    },
  });
  const body = await res.text();
  if (!res.ok) {
    /* The public endpoints rate limit rather than fail. Say so plainly so a
       model waits instead of retrying in a loop. */
    const retry = res.headers.get("retry-after");
    throw new Error(
      res.status === 429
        ? `rate limited${retry ? `, retry after ${retry}s` : ""}. These endpoints are free and shared; slow down rather than retry immediately.`
        : `HTTP ${res.status}: ${body.slice(0, 400)}`,
    );
  }
  try {
    return JSON.parse(body);
  } catch {
    return { raw: body };
  }
}

/* The agent signup doors (api.ffraud.com/v1/agent/...). Their 202 (still waiting for the
   person) and 410 (denied, expired, or the key handed over already) are answers to act on,
   so they come back as they are; a refusal (a limit, an address mail can't reach) is an
   error with the server's own words. */
async function agentApi(method, path, { body, bearer } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      accept: "application/json",
      "user-agent": UA,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = null;
  try {
    data = await res.json();
  } catch {}
  if (res.ok || res.status === 410) return data ?? { status: res.status };
  throw new Error(data?.message ?? `HTTP ${res.status}`);
}

const one = (v) => (Array.isArray(v) ? v[0] : v);
const list = (v, cap) => (Array.isArray(v) ? v : [v]).map(String).filter(Boolean).slice(0, cap);

/* ---------------------------------------------------------------- */
/* The tools                                                         */
/* ---------------------------------------------------------------- */

const TOOLS = {
  /* A whole website in seconds (2026-11-10): the same tool, words and answer
     as the remote server's (website/src/app/api/mcp/route.ts). */
  site_check: {
    description:
      "Check a whole website's security in seconds: the TLS certificate (trusted by browsers, expiry, the names it covers), the security headers (HSTS, Content-Security-Policy, framing, nosniff, referrer and permissions policies), cookie flags, whether http:// moves to https://, the domain's mail records (SPF, DMARC, MX), whether the domain or the addresses serving it are on phishing or abuse lists, and the bot protection the home page loads. Returns a 0-100 score, a grade from A to F, every finding with the exact fix to apply (header lines, DNS records, server settings), and what passed. Reads only what any visitor sees. Free, no key: 20 fresh checks an hour per address, 300 per account with a free key; a site checked in the last ten minutes costs nothing.",
    inputSchema: {
      type: "object",
      properties: {
        site: { type: "string", description: "The site's domain or any URL of it, e.g. example.com or https://example.com/login" },
        fresh: {
          type: "boolean",
          description: "true after the site was changed, to check it again now instead of reading the answer kept for ten minutes. A site is checked at most once a minute.",
        },
      },
      required: ["site"],
    },
    async run({ site, fresh }) {
      const host = String(one(site) ?? "")
        .trim()
        .replace(/^https?:\/\//i, "")
        .replace(/[/?#].*$/, "")
        .replace(/:\d+$/, "")
        .toLowerCase();
      if (!host.includes(".")) throw new Error("give the site's domain, e.g. example.com");
      const again = one(fresh) === true || one(fresh) === "true";
      if (KEY) {
        return api("/v1/site/check", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url: host, fresh: again }),
        });
      }
      return api(`/public/site/${encodeURIComponent(host)}${again ? "?fresh=1" : ""}`);
    },
  },

  ip_check: {
    description:
      "Fraud intelligence for any IPv4 or IPv6 address: a 0-100 fraud score, risk band, and whether it is a VPN, proxy, Tor node, relay, datacenter host or mobile connection. Also returns the owning network (ASN, ISP, organisation), geolocation, reverse DNS, abuse history and how much of its /24 subnet is flagged. Free, no key. Use it before trusting a signup, a checkout or an API caller.",
    inputSchema: {
      type: "object",
      properties: {
        ips: {
          type: "array",
          items: { type: "string" },
          maxItems: 50,
          description: "IPv4 or IPv6 addresses. One is the common case.",
        },
      },
      required: ["ips"],
    },
    async run({ ips }) {
      const addrs = list(ips, 50);
      if (!addrs.length) throw new Error("give at least one IP address");
      if (addrs.length === 1) return api(`/public/ip/${encodeURIComponent(addrs[0])}`);
      /* The batch endpoint wants a key; without one, fan out over the public
         route rather than failing, so the tool works for everybody. */
      if (KEY) {
        return api("/v1/ip/batch", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ips: addrs }),
        });
      }
      const results = [];
      for (const ip of addrs) {
        try {
          results.push(await api(`/public/ip/${encodeURIComponent(ip)}`));
        } catch (e) {
          results.push({ ip, error: String(e.message ?? e) });
        }
      }
      return { count: results.length, results };
    },
  },

  email_check: {
    description:
      "Check an email address before you let it create an account: whether it is disposable or throwaway, a role address, on a community blacklist, or tied to a domain that hands out temporary mailboxes. Free, no key.",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "A full email address, e.g. someone@mailinator.com" },
      },
      required: ["email"],
    },
    async run({ email }) {
      const addr = String(one(email) ?? "").trim();
      if (!addr.includes("@")) throw new Error("give a full email address, e.g. someone@example.com");
      return api("/public/email/check", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: addr }),
      });
    },
  },

  domain_check: {
    description:
      "Reputation for a domain: whether it hands out disposable mailboxes and whether it appears in the phishing dataset, with a risk level. One unauthenticated lookup, no key.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "A bare domain, e.g. mailinator.com (no scheme, no path)" },
      },
      required: ["domain"],
    },
    async run({ domain }) {
      const d = String(one(domain) ?? "")
        .trim()
        .replace(/^https?:\/\//i, "")
        .replace(/\/.*$/, "");
      if (!d.includes(".")) throw new Error("give a bare domain, e.g. example.com");
      return api(`/public/domain/${encodeURIComponent(d)}`);
    },
  },

  ip_reports: {
    description:
      "The community abuse reports filed against an IP: what it was reported for, when, and by how many distinct reporters. Use it when you want the evidence behind a score rather than the score alone.",
    inputSchema: {
      type: "object",
      properties: {
        ip: { type: "string", description: "The IPv4 or IPv6 address to read reports for." },
      },
      required: ["ip"],
    },
    async run({ ip }) {
      const addr = String(one(ip) ?? "").trim();
      if (!addr) throw new Error("give an IP address");
      return api(`/public/ip/${encodeURIComponent(addr)}/reports`);
    },
  },

  request_api_key: {
    description:
      "Ask FFraud for an API key for the person you work for. FFraud emails them one Approve button, and nothing is created until they press it. Returns signup_id and claim_token: tell the person to open the email from FFraud and press Approve, then call claim_api_key with both. Use it only when the person wants a key and gave you their own email address.",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "The person's own email address; the approval email goes there." },
        agent: { type: "string", description: 'Your name as the person knows you, e.g. "Claude Code". The email shows it.' },
      },
      required: ["email"],
    },
    acts: true,
    async run({ email, agent }) {
      const e = String(one(email) ?? "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) throw new Error("give the person's email address");
      return agentApi("POST", "/v1/agent/signup", { body: { email: e, agent: String(one(agent) ?? "").slice(0, 80) } });
    },
  },

  claim_api_key: {
    description:
      'After request_api_key: picks up the API key once the person pressed Approve. Answers status "pending" while they have not (wait about 5 seconds and call again, or remind them to check their inbox), "approved" with api_key exactly once (keep it: send it in the X-API-Key header, store it as FFRAUD_API_KEY), or "denied", "expired" or "delivered" when it is over.',
    inputSchema: {
      type: "object",
      properties: {
        signup_id: { type: "string", description: "The signup_id request_api_key returned." },
        claim_token: { type: "string", description: "The claim_token request_api_key returned." },
      },
      required: ["signup_id", "claim_token"],
    },
    acts: true,
    async run({ signup_id, claim_token }) {
      const id = String(one(signup_id) ?? "").trim();
      const claim = String(one(claim_token) ?? "").trim();
      if (!/^[0-9a-f-]{36}$/i.test(id) || !/^[0-9a-f]{64}$/i.test(claim)) throw new Error("give the signup_id and claim_token that request_api_key returned");
      return agentApi("GET", `/v1/agent/signup/${id}`, { bearer: claim });
    },
  },
};

const TITLES = {
  site_check: "Website security check",
  ip_check: "IP check",
  email_check: "Email check",
  domain_check: "Domain check",
  ip_reports: "IP abuse reports",
  request_api_key: "Get an FFraud API key",
  claim_api_key: "Pick up the approved key",
};

/* ---------------------------------------------------------------- */
/* MCP over stdio                                                    */
/* ---------------------------------------------------------------- */

const send = (msg) => process.stdout.write(JSON.stringify(msg) + "\n");
const ok = (id, result) => send({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => send({ jsonrpc: "2.0", id, error: { code, message } });

async function handle(msg) {
  const { id, method, params } = msg;
  /* A notification carries no id and takes no answer. */
  const wants = id !== undefined && id !== null;

  if (method === "initialize") {
    return (
      wants &&
      ok(id, {
        protocolVersion: PROTOCOLS.includes(params?.protocolVersion) ? params.protocolVersion : PROTOCOLS[0],
        capabilities: { tools: {} },
        serverInfo: { name: "ffraud", version: VERSION },
        instructions:
          "FFraud's open fraud database. site_check checks a whole website's security in seconds and returns every finding with the exact fix; ip_check scores any IP for VPN, proxy, Tor, datacenter and abuse history; email_check catches disposable and blacklisted addresses; domain_check reads a domain's phishing and throwaway-mailbox record; ip_reports returns the community evidence behind a score. All free and keyless; a free key raises site_check's hourly allowance. To get one without a browser: request_api_key emails the person an Approve button, and after their click claim_api_key returns the key once.",
      })
    );
  }
  if (method === "notifications/initialized" || method === "initialized") return;
  if (method === "ping") return wants && ok(id, {});
  if (method === "tools/list") {
    return (
      wants &&
      ok(id, {
        tools: Object.entries(TOOLS).map(([name, t]) => ({
          name,
          title: TITLES[name],
          description: t.description,
          inputSchema: t.inputSchema,
          /* A check only reads and asks the outside world: a client that confirms every
             write (ChatGPT treats a tool without readOnlyHint as one) need not ask. The two
             key tools act (an email, a key), so the client asks the person first. The same
             as the remote server's (website/src/app/api/mcp/route.ts). */
          annotations: t.acts
            ? { title: TITLES[name], readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true }
            : { title: TITLES[name], readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        })),
      })
    );
  }
  if (method === "tools/call") {
    const tool = TOOLS[params?.name];
    if (!tool) return wants && err(id, -32602, `no such tool: ${params?.name}`);
    try {
      const out = await tool.run(params?.arguments ?? {});
      /* Compact for the model, which reads (and pays for) every character: indented JSON is 17 to 21 percent
         longer on these answers (measured 2026-11-18). The command line still prints it indented for people. */
      return wants && ok(id, { content: [{ type: "text", text: JSON.stringify(out) }] });
    } catch (e) {
      /* A tool failure is a RESULT with isError, not a protocol error: the
         model should read the reason and adapt, not watch the call vanish. */
      return wants && ok(id, { content: [{ type: "text", text: String(e.message ?? e) }], isError: true });
    }
  }
  if (wants) err(id, -32601, `unknown method: ${method}`);
}

function serve() {
  let buf = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buf += chunk;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        /* JSON-RPC answers a line it cannot read with a parse error, so the client is not left waiting. */
        send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error: a line on stdin was not JSON" } });
        continue;
      }
      Promise.resolve(handle(msg)).catch((e) => process.stderr.write(`ffraud: ${e}\n`));
    }
  });
  process.stderr.write(`ffraud ${VERSION} MCP server ready on stdio (${BASE})\n`);
}

/* ---------------------------------------------------------------- */
/* The same tools as a CLI                                           */
/* ---------------------------------------------------------------- */

const USAGE = `ffraud ${VERSION}: the open fraud database, no key needed

Set it up
  ffraud setup [app] [--json]           the exact steps for your AI app (Claude Code,
                                        Claude Desktop, ChatGPT, Cursor, VS Code,
                                        Windsurf, Gemini CLI, Codex), or for all of them
  ffraud doctor                         check that everything works from this computer

Use it
  ffraud site <domain> [--fresh]        a whole website's security, every fix
                                        (--fresh: check again after a change)
  ffraud ip <address> [address ...]     fraud score, VPN/proxy/Tor, network, abuse
  ffraud email <address>                disposable, role, blacklisted
  ffraud domain <domain>                phishing and throwaway-mailbox record
  ffraud reports <address>              the community evidence behind a score
  ffraud signup <email> [--agent name]  an API key: FFraud emails <email> one
                                        Approve button, this waits for the click
                                        (up to 30 minutes) and prints the key once
  ffraud claim <signup_id> <claim_token>
                                        pick up an approved key later
  ffraud mcp                            run as an MCP server over stdio

Every check prints JSON. Nothing to install for apps that take a remote MCP
server: ${HOSTED}
Docs: https://ffraud.com/docs/mcp
`;

/* ---------------------------------------------------------------- */
/* setup: the exact steps for each app                               */
/* ---------------------------------------------------------------- */

/* Each app's line for the hosted server, as FFraud's docs print them (website/src/lib/docs/content/mcp.ts and
   ai-tutorials.ts, checked against each app's own docs on 2026-11-10), and the same tools started from this
   package for apps that only run local programs. */
const LOCAL_JSON = '{ "mcpServers": { "ffraud": { "command": "npx", "args": ["-y", "ffraud", "mcp"] } } }';
const APPS = [
  { name: "Claude Code", where: "In a terminal:", how: `claude mcp add --transport http ffraud ${HOSTED}`, local: "claude mcp add ffraud -- npx -y ffraud mcp" },
  {
    name: "Claude and Claude Desktop",
    where: "Settings, Connectors, Add custom connector, then paste the address:",
    how: HOSTED,
    local: `In Claude Desktop's settings file (Settings, Developer, Edit Config):\n${LOCAL_JSON}`,
  },
  {
    name: "ChatGPT",
    where: "Open Plugins, select the plus button, choose Add custom MCP server, name it FFraud, enter this address under Connection and choose No authentication:",
    how: HOSTED,
    local: null,
  },
  { name: "Cursor", where: "In ~/.cursor/mcp.json:", how: `{ "mcpServers": { "ffraud": { "url": "${HOSTED}" } } }`, local: `In ~/.cursor/mcp.json:\n${LOCAL_JSON}` },
  {
    name: "VS Code",
    where: "In .vscode/mcp.json:",
    how: `{ "servers": { "ffraud": { "type": "http", "url": "${HOSTED}" } } }`,
    local: 'In .vscode/mcp.json:\n{ "servers": { "ffraud": { "type": "stdio", "command": "npx", "args": ["-y", "ffraud", "mcp"] } } }',
  },
  {
    name: "Windsurf",
    where: "In ~/.codeium/windsurf/mcp_config.json:",
    how: `{ "mcpServers": { "ffraud": { "serverUrl": "${HOSTED}" } } }`,
    local: `In ~/.codeium/windsurf/mcp_config.json:\n${LOCAL_JSON}`,
  },
  { name: "Gemini CLI", where: "In ~/.gemini/settings.json:", how: `{ "mcpServers": { "ffraud": { "httpUrl": "${HOSTED}" } } }`, local: `In ~/.gemini/settings.json:\n${LOCAL_JSON}` },
  {
    name: "Codex",
    where: "In a terminal:",
    how: `codex mcp add ffraud --url ${HOSTED}`,
    local: 'In ~/.codex/config.toml:\n[mcp_servers.ffraud]\ncommand = "npx"\nargs = ["-y", "ffraud", "mcp"]',
  },
];

const squash = (s) => String(s).toLowerCase().replace(/[^a-z0-9]/g, "");

function setup(app, asJson) {
  const wanted = app ? squash(app) : "";
  const apps = APPS.filter((a) => !wanted || squash(a.name).includes(wanted));
  if (wanted && !apps.length) {
    throw new Error(`no app called "${app}". The apps: ${APPS.map((a) => a.name).join(", ")}. Without a name, setup prints all of them.`);
  }
  if (asJson) {
    return {
      hosted: { url: HOSTED, transport: "streamable-http", authentication: "none" },
      local: { command: "npx", args: ["-y", "ffraud", "mcp"], transport: "stdio" },
      apps: apps.map((a) => ({ name: a.name, where: a.where, line: a.how, local: a.local })),
      docs: "https://ffraud.com/docs/mcp",
    };
  }
  const out = ["Add FFraud's fraud checks to your AI app. No key, no account.", "", "Apps that take a remote MCP server need nothing installed. The address:", `  ${HOSTED}`];
  for (const a of apps) {
    out.push("", a.name, `  ${a.where}`, ...a.how.split("\n").map((l) => `  ${l}`));
    if (a.local) out.push("  Or start it on this computer instead (Node 18 or newer):", ...a.local.split("\n").map((l) => `  ${l}`));
  }
  if (!wanted) {
    out.push("", "Any other app", `  A remote MCP server at ${HOSTED} (Streamable HTTP, no authentication),`, '  or a local one: command "npx", arguments "-y", "ffraud" and "mcp".');
  }
  out.push("", "Check it from this computer: npx ffraud doctor", 'Then ask your assistant: "Check the security of example.com and tell me what to fix."');
  return out.join("\n");
}

/* ---------------------------------------------------------------- */
/* doctor: does it work from this computer?                          */
/* ---------------------------------------------------------------- */

async function doctor() {
  const out = [`ffraud ${VERSION} doctor`];
  let good = true;
  const step = (ok, what) => {
    out.push(`${ok ? "  ok    " : "  FAIL  "}${what}`);
    if (!ok) good = false;
  };
  const major = Number(process.versions.node.split(".")[0]);
  step(major >= 18, `Node ${process.versions.node}${major >= 18 ? "" : ": this package needs Node 18 or newer"}`);
  try {
    const t0 = Date.now();
    const ip = await api("/public/ip/8.8.8.8");
    step(typeof ip?.fraud_score === "number", `${BASE} answers a check: ip 8.8.8.8 scores ${ip?.fraud_score} (${Date.now() - t0} ms)`);
  } catch (e) {
    step(false, `${BASE} could not be reached: ${e.message ?? e}`);
  }
  try {
    const t0 = Date.now();
    const res = await fetch(HOSTED, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "user-agent": UA },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "ffraud-doctor", version: VERSION } } }),
      signal: AbortSignal.timeout(20000),
    });
    const text = await res.text();
    const data = (text.match(/\{.*\}/s) || [""])[0];
    let name = null;
    try {
      name = JSON.parse(data)?.result?.serverInfo?.name;
    } catch {}
    step(res.ok && !!name, `the hosted MCP server ${HOSTED} answers the handshake (HTTP ${res.status}, ${Date.now() - t0} ms)`);
  } catch (e) {
    step(false, `the hosted MCP server ${HOSTED} could not be reached: ${e.message ?? e}`);
  }
  out.push("", good ? "Everything works. Add it to your app: npx ffraud setup" : "Something above failed. Help: team@ffraud.com, docs: https://ffraud.com/docs/mcp");
  return { text: out.join("\n"), good };
}

/* `ffraud signup`: the two key tools in a row. The waiting is said on stderr, so stdout
   carries only the answer (the key, once). */
async function signup(email, agent) {
  const asked = await TOOLS.request_api_key.run({ email, agent: agent || "ffraud CLI" });
  if (!asked?.signup_id) throw new Error(asked?.message ?? "FFraud did not take the request");
  process.stderr.write(`FFraud emailed ${email} an Approve button. Open the email from FFraud and press Approve; this waits up to 30 minutes.\n`);
  const until = Date.now() + 30 * 60 * 1000;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, Number(process.env.FFRAUD_POLL_MS) || 5000));
    const got = await TOOLS.claim_api_key.run({ signup_id: asked.signup_id, claim_token: asked.claim_token });
    if (got?.status === "pending") continue;
    if (got?.status === "approved") {
      process.stderr.write("Approved. The key is shown this once: keep it as FFRAUD_API_KEY.\n");
      return got;
    }
    throw new Error(got?.message ?? `the request is ${got?.status}`);
  }
  throw new Error(`nobody pressed Approve within 30 minutes. The email stays valid for 24 hours: after the click, run  ffraud claim ${asked.signup_id} ${asked.claim_token}`);
}

async function cli(argv) {
  const cmd = argv[0];
  const rest = argv.slice(1).filter((a) => !a.startsWith("--"));

  if (cmd === "setup") {
    const out = setup(rest[0], argv.includes("--json"));
    return typeof out === "string" ? new Text(out) : out;
  }
  if (cmd === "doctor") {
    const { text, good } = await doctor();
    if (!good) process.exitCode = 1;
    return new Text(text);
  }

  if (cmd === "site") return TOOLS.site_check.run({ site: rest[0], fresh: argv.includes("--fresh") });
  if (cmd === "ip") return TOOLS.ip_check.run({ ips: rest });
  if (cmd === "email") return TOOLS.email_check.run({ email: rest[0] });
  if (cmd === "domain") return TOOLS.domain_check.run({ domain: rest[0] });
  if (cmd === "reports") return TOOLS.ip_reports.run({ ip: rest[0] });
  if (cmd === "signup") {
    const at = argv.indexOf("--agent");
    const agent = at > 0 ? argv[at + 1] ?? "" : "";
    const email = argv.slice(1).find((a, i) => !a.startsWith("--") && argv[i] !== "--agent");
    return signup(email, agent);
  }
  if (cmd === "claim") return TOOLS.claim_api_key.run({ signup_id: rest[0], claim_token: rest[1] });
  return null;
}

/* What a command prints as written (setup, doctor), beside the checks, which print JSON. */
class Text {
  constructor(text) {
    this.text = text;
  }
}

const argv = process.argv.slice(2);
if (!argv.length || argv[0] === "mcp") {
  serve();
} else if (argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
  process.stdout.write(USAGE);
} else if (argv[0] === "--version" || argv[0] === "-v") {
  process.stdout.write(VERSION + "\n");
} else {
  cli(argv)
    .then((out) => {
      if (out === null) {
        process.stderr.write(USAGE);
        process.exit(2);
      }
      process.stdout.write((out instanceof Text ? out.text : JSON.stringify(out, null, 2)) + "\n");
    })
    .catch((e) => {
      process.stderr.write(`ffraud: ${e.message ?? e}\n`);
      process.exit(1);
    });
}
