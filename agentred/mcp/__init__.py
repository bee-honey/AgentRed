"""A minimal, faithful MCP implementation over stdio (JSON-RPC 2.0).

This is a small, self-contained subset of the Model Context Protocol — enough to
run a real client/server boundary (initialize handshake, tools/list, tools/call)
so AgentRed can record tool traffic at the protocol level rather than in-process.

It follows the wire shape of the spec (newline-delimited JSON-RPC 2.0 messages,
`inputSchema` on tools, `content` blocks on results) so a real MCP peer could be
swapped in later, but it is deliberately not a full implementation.
"""
