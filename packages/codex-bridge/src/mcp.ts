// Copyright 2026 Ix Infrastructure Inc.
//
// A minimal MCP server over stdio: newline-delimited JSON-RPC 2.0, as the
// MCP stdio transport specifies (one message per line, nothing else on
// stdout). Just what the bridge needs: initialize, ping, tools/list,
// tools/call, and server-to-client requests (elicitation/create, roots/list).
// No SDK dependency, so the bundled `p2p.mjs` stays one self-contained file.

export const PROTOCOL_VERSION = "2025-06-18";
const SUPPORTED_VERSIONS = new Set(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]);

export type JsonObject = Record<string, unknown>;

export interface ToolResult {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: JsonObject;
}

export interface Tool {
  name: string;
  title?: string;
  description: string;
  inputSchema: JsonObject;
  annotations?: JsonObject;
  call(args: JsonObject, ctx: CallContext): Promise<ToolResult>;
}

export interface CallContext {
  /** Sends a request to the client (Codex) and waits for its answer. */
  request(method: string, params: JsonObject, timeoutMs?: number): Promise<unknown>;
  /** What the client said it can do at initialize. */
  clientCapabilities: JsonObject;
  /** The request's `_meta` (Codex puts its turn metadata there). */
  meta?: unknown;
}

export interface ServerInfo {
  name: string;
  version: string;
  instructions?: string;
}

type Pending = { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> };

export const text = (body: string, isError = false): ToolResult => ({ content: [{ type: "text", text: body }], ...(isError ? { isError: true } : {}) });

/**
 * Serves `tools` on a line-oriented transport. `write` gets one JSON line per
 * message; feed incoming lines to the returned `onLine`.
 */
export class McpServer {
  private readonly pending = new Map<number, Pending>();
  private nextId = 1;
  clientCapabilities: JsonObject = {};
  clientInfo: JsonObject = {};
  /** Called once the client sent `notifications/initialized`. */
  onInitialized?: () => void;
  /** Called for a tool name the server does not list (after the refusal). */
  onUnknownTool?: (name: string) => void;

  constructor(
    private readonly info: ServerInfo,
    private readonly tools: readonly Tool[],
    private readonly write: (line: string) => void,
    private readonly refuse: (name: string) => ToolResult | null = () => null,
  ) {}

  private send(msg: JsonObject): void {
    this.write(JSON.stringify({ jsonrpc: "2.0", ...msg }));
  }

  request(method: string, params: JsonObject, timeoutMs = 60_000): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out`));
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, reject, timer });
      this.send({ id, method, params });
    });
  }

  /** Rejects every request still waiting on the client (the transport closed). */
  close(): void {
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error("closed"));
      this.pending.delete(id);
    }
  }

  async onLine(line: string): Promise<void> {
    if (line.trim() === "") return;
    let msg: JsonObject;
    try {
      const v = JSON.parse(line);
      if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
      msg = v as JsonObject;
    } catch {
      this.send({ id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    const id = msg.id as number | string | undefined;
    const method = typeof msg.method === "string" ? msg.method : undefined;
    // A response to one of our requests.
    if (method === undefined) {
      if (typeof id === "number" && this.pending.has(id)) {
        const p = this.pending.get(id) as Pending;
        this.pending.delete(id);
        clearTimeout(p.timer);
        if (msg.error) p.reject(new Error(String((msg.error as JsonObject).message ?? "error")));
        else p.resolve(msg.result);
      }
      return;
    }
    const isNotification = id === undefined || id === null;
    try {
      const result = await this.dispatch(method, (msg.params ?? {}) as JsonObject);
      if (!isNotification) this.send({ id, result });
    } catch (e) {
      if (!isNotification) {
        const err = e as { code?: number; message?: string };
        this.send({ id, error: { code: typeof err.code === "number" ? err.code : -32603, message: String(err.message ?? e) } });
      }
    }
  }

  private async dispatch(method: string, params: JsonObject): Promise<unknown> {
    switch (method) {
      case "initialize": {
        this.clientCapabilities = (params.capabilities ?? {}) as JsonObject;
        this.clientInfo = (params.clientInfo ?? {}) as JsonObject;
        const asked = typeof params.protocolVersion === "string" ? params.protocolVersion : PROTOCOL_VERSION;
        return {
          protocolVersion: SUPPORTED_VERSIONS.has(asked) ? asked : PROTOCOL_VERSION,
          capabilities: { tools: { listChanged: false } },
          serverInfo: { name: this.info.name, version: this.info.version },
          ...(this.info.instructions ? { instructions: this.info.instructions } : {}),
        };
      }
      case "notifications/initialized":
        this.onInitialized?.();
        return {};
      case "ping":
        return {};
      case "tools/list":
        return {
          tools: this.tools.map((t) => ({
            name: t.name,
            ...(t.title ? { title: t.title } : {}),
            description: t.description,
            inputSchema: t.inputSchema,
            ...(t.annotations ? { annotations: t.annotations } : {}),
          })),
        };
      case "tools/call": {
        const name = String(params.name ?? "");
        const args = (typeof params.arguments === "object" && params.arguments !== null ? params.arguments : {}) as JsonObject;
        const tool = this.tools.find((t) => t.name === name);
        if (!tool) {
          this.onUnknownTool?.(name);
          return this.refuse(name) ?? text(`Unknown tool: ${name.replace(/[^\w.-]/g, "").slice(0, 64)}`, true);
        }
        try {
          return await tool.call(args, { request: (m, p, t) => this.request(m, p, t), clientCapabilities: this.clientCapabilities, meta: params._meta });
        } catch (e) {
          return text(`${name} failed: ${String((e as Error)?.message ?? e).replace(/[<>\p{Cc}\p{Cf}]/gu, " ")}`, true);
        }
      }
      case "resources/list":
        return { resources: [] };
      case "prompts/list":
        return { prompts: [] };
      default:
        if (method.startsWith("notifications/")) return {};
        throw Object.assign(new Error(`Method not found: ${method}`), { code: -32601 });
    }
  }
}

/**
 * Splits a stream into lines and hands each to the server as it arrives.
 * Not serialised: a tool call that waits on the client (elicitation) must not
 * block the line that carries the client's answer.
 */
export function lineFeeder(onLine: (line: string) => Promise<void>): { push(chunk: string): void; end(): Promise<void> } {
  let buffer = "";
  const inflight = new Set<Promise<void>>();
  const run = (line: string) => {
    const p = onLine(line.replace(/\r$/, "")).catch(() => undefined);
    inflight.add(p);
    void p.finally(() => inflight.delete(p));
  };
  return {
    push(chunk: string) {
      buffer += chunk;
      const parts = buffer.split("\n");
      buffer = parts.pop() ?? "";
      for (const line of parts) run(line);
    },
    async end() {
      if (buffer.trim() !== "") run(buffer);
      buffer = "";
      await Promise.all([...inflight]);
    },
  };
}
