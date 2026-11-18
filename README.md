<p align="center">
  <a href="https://ffraud.com"><img src="https://ffraud.com/apple-touch-icon.png" width="72" height="72" alt="FFraud"></a>
</p>

<h1 align="center">ffraud</h1>

<p align="center">
  The official CLI and MCP server of <a href="https://ffraud.com">FFraud</a>, the free fraud-detection API.<br>
  <a href="https://ffraud.com">Website</a> · <a href="https://ffraud.com/docs">Docs</a> · <a href="https://ffraud.com/docs/mcp">MCP setup</a> · <a href="https://ffraud.com/openapi.json">OpenAPI</a>
</p>

FFraud's open fraud database as a **CLI** and an **MCP server**. Five checks with no key, and a key by one email when you want one.

**The quickest way.** Ask your assistant to run this and follow what it prints, or run it yourself:

```bash
npx -y ffraud setup
```

It prints the exact steps for each app (Claude Code, Claude Desktop, ChatGPT, Cursor, VS Code, Windsurf, Gemini CLI, Codex). `npx -y ffraud setup cursor` prints one app, `--json` gives the same to a program, and `npx -y ffraud doctor` checks that everything works from your computer.

```bash
npx ffraud site example.com      # a whole website's security, every finding with its fix
npx ffraud ip 185.220.101.34     # fraud score, VPN, proxy, Tor, network, abuse
```

| tool | what it answers |
| --- | --- |
| `site_check` | How secure is this whole website? Certificate, security headers, cookies, http to https, SPF, DMARC and MX, the domain and its addresses in FFraud's data, bot protection: a 0-100 score, a grade, and every finding with the exact fix. |
| `ip_check` | Is this IP a VPN, proxy, Tor node, relay or datacenter host? What is its 0-100 fraud score, who runs the network, where is it, and how much of its /24 is flagged? |
| `email_check` | Is this address disposable, a role account, or community-blacklisted? |
| `domain_check` | Does this domain hand out throwaway mailboxes, or appear in the phishing dataset? |
| `ip_reports` | What did the community actually report this IP for, and when? |
| `request_api_key` | Get the person you work for an API key: FFraud emails them one Approve button, and nothing is created until they press it. |
| `claim_api_key` | Pick up that key once they approved. It is handed over exactly once. |

## Use it as a CLI

```bash
npx ffraud site example.com
npx ffraud site example.com --fresh   # again, after you changed the site
npx ffraud ip 45.33.32.156
npx ffraud email throwaway@mailinator.com
npx ffraud domain mailinator.com
npx ffraud reports 45.33.32.156
npx ffraud signup you@example.com     # a key: one approval email, then the key, once
```

Every command prints JSON, so it pipes into `jq` like anything else. `npm install -g ffraud` puts `ffraud` on your path.

## Use it as an MCP server

The same seven tools run on ffraud.com as a remote MCP server, with nothing to install: `https://ffraud.com/api/mcp`
(Streamable HTTP). Claude Code: `claude mcp add --transport http ffraud https://ffraud.com/api/mcp`. Every client,
step by step: https://ffraud.com/docs/mcp

For a client that runs local servers, this package speaks MCP over stdio:

```json
{
  "mcpServers": {
    "ffraud": {
      "command": "npx",
      "args": ["-y", "ffraud", "mcp"]
    }
  }
}
```

Claude Code: `claude mcp add ffraud -- npx -y ffraud mcp`

It speaks JSON-RPC 2.0 over stdio. stdout is the protocol, so every log line goes to stderr.

## Keys

The checks need none: each calls a public endpoint.

To get one without a browser, `npx ffraud signup you@example.com` (or the tools `request_api_key` and `claim_api_key`): FFraud emails that address one Approve button, the command waits for the click and prints the key once. A new address chooses its password on the approval page, so the account has a way into the dashboard. Without the click nothing is created.

`FFRAUD_API_KEY` is forwarded as `X-API-Key` when set (the only header the engine reads a key from), which raises burst limits and site_check's hourly allowance, and nothing else. No tool in this package can spend money. Only the two key tools change anything: `request_api_key` sends the person one email, and a key exists only after their click. `FFRAUD_BASE_URL` overrides the API base for local development.

## Batch behavior worth knowing

`ip_check` takes up to 50 addresses. With a key it uses the batch endpoint in one call; without one it fans out over the public route rather than failing, so the tool works for everybody. A single address always takes the single-address path.

## Rate limits

The public endpoints rate limit rather than fail. A 429 comes back as a readable message with the retry delay, so a model waits instead of retrying in a loop.

`site_check` reaches out to a real website, so it has an hourly allowance: 20 fresh checks per address without a key, 300 per account with one. A site checked in the last ten minutes answers from memory and costs nothing; after a change, `fresh: true` (CLI: `--fresh`) checks again unless the site was checked in the last minute. The four lookups have no usage caps.

## Zero dependencies

Node 18+ has `fetch`. An assistant that has to install a dependency tree before it can check an IP will not bother, so there is nothing to install.

## Related

- MCP docs: https://ffraud.com/docs/mcp
- API docs: https://ffraud.com/docs
- OpenAPI spec: https://ffraud.com/openapi.json
- For AI: https://ffraud.com/llms.txt and https://ffraud.com/llms-full.txt
- Open data (MIT): https://github.com/FFraud-com
