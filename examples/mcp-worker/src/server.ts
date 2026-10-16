
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

  // TEMPORÁRIO: diagnóstico de escrita e leitura do AUTH_KV
  server.registerTool(
    "test_auth_kv",
    {
      description: "Temporary diagnostic for AUTH_KV write/read",
      inputSchema: {}
    },
    async () => {
      const key = "diagnostic:auth-kv-test";
      const expected = "AUTH_KV_WRITE_READ_OK";

      try {
        if (!env?.AUTH_KV) {
          throw new Error("O binding AUTH_KV não está disponível.");
        }

        await env.AUTH_KV.put(key, expected);
        const actual = await env.AUTH_KV.get(key);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                writeAttempted: true,
                readSucceeded: actual !== null,
                valuesMatch: actual === expected,
                result:
                  actual === expected ? "PASS" : "FAIL"
              })
            }
          ]
        };
      } catch (error) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                result: "ERROR",
                message:
                  error instanceof Error
                    ? error.message
                    : String(error)
              })
            }
          ]
        };
      }
    }
  );

  return server;
}

export default {
  fetch(request, env, ctx) {
    return createMcpHandler(() => createServer(env as Env))(
      request,
      env,
      ctx
    );
  }
} satisfies ExportedHandler;
