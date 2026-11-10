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

   Zero dependencies on purpose: node 18+ has fetch, and an assistant
   that must install a tree before it can check an IP will not bother.

   Keys: every tool here uses a PUBLIC endpoint and needs no key. If
   FFRAUD_API_KEY is set it is forwarded, which raises burst limits and
   site_check's hourly allowance (20 fresh checks per address, 300 per
   account) and nothing else. Nothing here can spend money or change an
   account.
   ============================================================ */

const BASE = process.env.FFRAUD_BASE_URL ?? "https://api.ffraud.com";
const KEY = process.env.FFRAUD_API_KEY ?? "";
const VERSION = "1.1.1";
const UA = `ffraud/${VERSION} (+https://ffraud.com/docs/mcp)`;

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
};

const TITLES = {
  site_check: "Website security check",
  ip_check: "IP check",
  email_check: "Email check",
  domain_check: "Domain check",
  ip_reports: "IP abuse reports",
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
        protocolVersion: params?.protocolVersion ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "ffraud", version: VERSION },
        instructions:
          "FFraud's open fraud database. site_check checks a whole website's security in seconds and returns every finding with the exact fix; ip_check scores any IP for VPN, proxy, Tor, datacenter and abuse history; email_check catches disposable and blacklisted addresses; domain_check reads a domain's phishing and throwaway-mailbox record; ip_reports returns the community evidence behind a score. All free and keyless; a free key from ffraud.com/dashboard/keys raises site_check's hourly allowance.",
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
          /* Read only, asking the outside world: a client that confirms every write
             (ChatGPT treats a tool without readOnlyHint as one) need not ask. The
             same as the remote server's (website/src/app/api/mcp/route.ts). */
          annotations: { title: TITLES[name], readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
        })),
      })
    );
  }
  if (method === "tools/call") {
    const tool = TOOLS[params?.name];
    if (!tool) return wants && err(id, -32602, `no such tool: ${params?.name}`);
    try {
      const out = await tool.run(params?.arguments ?? {});
      return wants && ok(id, { content: [{ type: "text", text: JSON.stringify(out, null, 2) }] });
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

const USAGE = `ffraud ${VERSION} — the open fraud database, no key needed

  ffraud site <domain> [--fresh]        a whole website's security, every fix
                                        (--fresh: check again after a change)
  ffraud ip <address> [address ...]     fraud score, VPN/proxy/Tor, network, abuse
  ffraud email <address>                disposable, role, blacklisted
  ffraud domain <domain>                phishing and throwaway-mailbox record
  ffraud reports <address>              the community evidence behind a score
  ffraud mcp                            run as an MCP server over stdio

Every command prints JSON. Docs: https://ffraud.com/docs
`;

async function cli(argv) {
  const cmd = argv[0];
  const rest = argv.slice(1).filter((a) => !a.startsWith("--"));

  if (cmd === "site") return TOOLS.site_check.run({ site: rest[0], fresh: argv.includes("--fresh") });
  if (cmd === "ip") return TOOLS.ip_check.run({ ips: rest });
  if (cmd === "email") return TOOLS.email_check.run({ email: rest[0] });
  if (cmd === "domain") return TOOLS.domain_check.run({ domain: rest[0] });
  if (cmd === "reports") return TOOLS.ip_reports.run({ ip: rest[0] });
  return null;
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
      process.stdout.write(JSON.stringify(out, null, 2) + "\n");
    })
    .catch((e) => {
      process.stderr.write(`ffraud: ${e.message ?? e}\n`);
      process.exit(1);
    });
}
