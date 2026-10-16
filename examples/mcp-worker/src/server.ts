
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

type Env = {
  AUTH_KV: KVNamespace;
};

function createServer(env: Env) {
  const server = new McpServer({
    name: "Hello MCP Server",
    version: "1.0.0"
  });

  server.registerTool(
    "hello",
    {
      description: "Returns a greeting message",
      inputSchema: { name: z.string().optional() }
    },
    async ({ name }) => {
      return {
        content: [
          {
            text: `Hello, ${name ?? "World"}!`,
            type: "text"
          }
        ]
      };
    }
  );
