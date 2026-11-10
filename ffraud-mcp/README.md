# ffraud-mcp

The first name of FFraud's MCP server. It runs the [`ffraud`](https://www.npmjs.com/package/ffraud) package, so
both names give the same five tools: a whole website's security, IP fraud scoring, disposable-email and domain
checks, and community abuse reports. No key needed.

```bash
npx ffraud site example.com     # the CLI, under its current name
npx -y ffraud-mcp               # MCP over stdio, under this name
```

MCP clients, step by step: https://ffraud.com/docs/mcp
