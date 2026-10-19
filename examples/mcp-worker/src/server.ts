
import { McpServer } from "@modelcontextprotocol/server";
import { createMcpHandler } from "agents/mcp/server";
import { z } from "zod";

type Env = {
  AUTH_KV: KVNamespace;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;
  GOOGLE_TOKEN_ENCRYPTION_KEY: string;
};

const REDIRECT_URI =
  "https://playbot-business-os-mcp.playbotbusiness.workers.dev/oauth/google/callback";

const AUTHORIZED_EMAIL = "playbotbusiness@gmail.com";
const TOKEN_KEY = "google_tokens";

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function getEncryptionKey(env: Env): Uint8Array {
  const hex = env.GOOGLE_TOKEN_ENCRYPTION_KEY;

  const isString = typeof hex === "string";
  const length = isString ? hex.length : null;
  const validHex =
    isString && /^[0-9a-fA-F]{64}$/.test(hex);

  if (!validHex) {
    console.error("Encryption key validation failed", {
      isString,
      length,
      validHex
    });

    throw new Error("Invalid encryption key configuration");
  }

  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return bytes;
}

async function encryptTokens(
  env: Env,
  tokens: unknown
): Promise<string> {
  const keyBytes = getEncryptionKey(env);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(tokens));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    plaintext
  );

  return JSON.stringify({
    version: 1,
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  });
}


type GoogleTokens = {
  access_token?: string;
  refresh_token?: string;
  expires_at?: number;
  token_type?: string;
  scope?: string;
  email?: string;
};

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function decryptTokens(
  env: Env,
  encrypted: string
): Promise<GoogleTokens> {
  const record = JSON.parse(encrypted) as {
    version?: number;
    iv?: string;
    ciphertext?: string;
  };

  if (
    record.version !== 1 ||
    typeof record.iv !== "string" ||
    typeof record.ciphertext !== "string"
  ) {
    throw new Error("Invalid encrypted token record");
  }

  const key = await crypto.subtle.importKey(
    "raw",
    getEncryptionKey(env),
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: base64ToBytes(record.iv)
    },
    key,
    base64ToBytes(record.ciphertext)
  );

  return JSON.parse(
    new TextDecoder().decode(plaintext)
  ) as GoogleTokens;
}

async function getGoogleAccessToken(
  env: Env
): Promise<string> {
  const encrypted = await env.AUTH_KV.get(TOKEN_KEY);

  if (!encrypted) {
    throw new Error("Google authorization is missing");
  }

  const stored = await decryptTokens(env, encrypted);

  if (
    stored.access_token &&
    typeof stored.expires_at === "number" &&
    stored.expires_at > Date.now() + 60_000
  ) {
    return stored.access_token;
  }

  if (!stored.refresh_token) {
    throw new Error("Google refresh token is missing");
  }

  const response = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: env.GOOGLE_CLIENT_ID,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        refresh_token: stored.refresh_token,
        grant_type: "refresh_token"
      })
    }
  );

  if (!response.ok) {
    throw new Error(
      `Google token refresh failed (${response.status})`
    );
  }

  const refreshed = await response.json() as {
    access_token?: string;
    refresh_token?: string;
    expires_in?: number;
    token_type?: string;
    scope?: string;
  };

  if (!refreshed.access_token) {
    throw new Error("Google returned no access token");
  }

  const updated: GoogleTokens = {
    ...stored,
    access_token: refreshed.access_token,
    refresh_token:
      refreshed.refresh_token ?? stored.refresh_token,
    expires_at:
      Date.now() + (refreshed.expires_in ?? 3600) * 1000,
    token_type: refreshed.token_type ?? stored.token_type,
    scope: refreshed.scope ?? stored.scope
  };

  await env.AUTH_KV.put(
    TOKEN_KEY,
    await encryptTokens(env, updated)
  );

  return updated.access_token;
}

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
    async ({ name }) => ({
      content: [
        {
          text: `Hello, ${name ?? "World"}!`,
          type: "text"
        }
      ]
    })
  );

  
  server.registerTool(
    "google_drive_list_files",
    {
      description:
        "Lists Google Drive files accessible to PlayBot Business OS. Supports an optional Google Drive search query, page size, and page token.",
      inputSchema: {
        query: z.string().optional(),
        pageSize: z.number().int().min(1).max(100).optional(),
        pageToken: z.string().optional()
      }
    },
    async ({ query, pageSize, pageToken }) => {
      const accessToken = await getGoogleAccessToken(env);

      const params = new URLSearchParams({
        pageSize: String(pageSize ?? 20),
        fields:
          "nextPageToken,files(id,name,mimeType,modifiedTime,webViewLink)",
        q: query?.trim()
          ? `trashed = false and (${query.trim()})`
          : "trashed = false"
      });

      if (pageToken) {
        params.set("pageToken", pageToken);
      }

      const response = await fetch(
        `https://www.googleapis.com/drive/v3/files?${params}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(
          `Google Drive request failed (${response.status})`
        );
      }

      const result = await response.json() as {
        nextPageToken?: string;
        files?: Array<{
          id: string;
          name: string;
          mimeType?: string;
          modifiedTime?: string;
          webViewLink?: string;
        }>;
      };

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }
  );

  return server;
}

async function handleOAuth(
  request: Request,
  env: Env
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/oauth/google/start") {
    const state = crypto.randomUUID();

    await env.AUTH_KV.put(
      `oauth_state:${state}`,
      "pending",
      { expirationTtl: 600 }
    );

    const authorizationUrl = new URL(
      "https://accounts.google.com/o/oauth2/v2/auth"
    );

    authorizationUrl.search = new URLSearchParams({
      client_id: env.GOOGLE_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: "code",
      scope:
  "openid email https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/spreadsheets",
     state,
      access_type: "offline",
      prompt: "consent"
    }).toString();

    return Response.redirect(authorizationUrl.toString(), 302);
  }

  if (url.pathname === "/oauth/google/callback") {
    const error = url.searchParams.get("error");
    if (error) {
      return new Response(
        "Google authorization was not completed. Return to the Worker and try again.",
        { status: 400 }
      );
    }

    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state) {
      return new Response("Missing OAuth code or state.", {
        status: 400
      });
    }

    const stateKey = `oauth_state:${state}`;
    const savedState = await env.AUTH_KV.get(stateKey);

    if (!savedState) {
      return new Response(
        "Invalid or expired OAuth state. Start authorization again.",
        { status: 400 }
      );
    }

    await env.AUTH_KV.delete(stateKey);

    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code,
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          redirect_uri: REDIRECT_URI,
          grant_type: "authorization_code"
        })
      }
    );

    if (!tokenResponse.ok) {
      return new Response(
        "Google token exchange failed. Check the OAuth configuration.",
        { status: 502 }
      );
    }

    const tokens = (await tokenResponse.json()) as {
      access_token?: string;
      refresh_token?: string;
      expires_in?: number;
      token_type?: string;
      scope?: string;
    };

    if (!tokens.access_token) {
      return new Response("Google did not return an access token.", {
        status: 502
      });
    }

    const userResponse = await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`
        }
      }
    );

    if (!userResponse.ok) {
      return new Response(
        "Could not verify the Google account.",
        { status: 502 }
      );
    }

    const user = (await userResponse.json()) as {
      email?: string;
      email_verified?: boolean;
    };

    if (
      user.email?.toLowerCase() !== AUTHORIZED_EMAIL ||
      user.email_verified !== true
    ) {
      return new Response(
        "Access denied. Use the authorized Google account.",
        { status: 403 }
      );
    }

    const previous = await env.AUTH_KV.get(
      TOKEN_KEY,
      "json"
    ) as { refresh_token?: string } | null;

    const refreshToken =
      tokens.refresh_token ?? previous?.refresh_token;

    if (!refreshToken) {
      return new Response(
        "Google did not provide a refresh token. Restart authorization and approve offline access.",
        { status: 502 }
      );
    }

    const encrypted = await encryptTokens(env, {
      access_token: tokens.access_token,
      refresh_token: refreshToken,
      expires_at: Date.now() + (tokens.expires_in ?? 3600) * 1000,
      token_type: tokens.token_type,
      scope: tokens.scope,
      email: user.email
    });

    await env.AUTH_KV.put(TOKEN_KEY, encrypted);

    return new Response(
      "Google authorization completed and tokens were stored encrypted. You can close this page.",
      {
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store"
        }
      }
    );
  }

  return new Response("Not found.", { status: 404 });
}


export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/oauth/google/")) {
      try {
        return await handleOAuth(request, env as Env);
      } catch (error) {
        console.error(
          "OAuth processing failed:",
          error instanceof Error
            ? `${error.name}: ${error.message}`
            : "Unknown error"
        );

        return new Response(
          "OAuth processing failed. Check the Worker logs and configuration.",
          { status: 500 }
        );
      }
    }

    return createMcpHandler(() => createServer(env as Env))(
      request,
      env,
      ctx
    );
  }
} satisfies ExportedHandler;
