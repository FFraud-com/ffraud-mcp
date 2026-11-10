#!/usr/bin/env node
/* ffraud-mcp: the name FFraud's MCP server had first, kept so nobody else owns it. It runs the ffraud
   package itself (its index.mjs reads the same command line), so both names are one code base:
   `npx ffraud-mcp` serves MCP over stdio, `npx ffraud-mcp site example.com` is the CLI. */
import "ffraud";
