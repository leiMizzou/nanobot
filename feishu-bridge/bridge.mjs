import express from "express";
import { readFileSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import crypto from "crypto";

// ─── Load .env ────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(__dirname, ".env");
try {
  const envContent = readFileSync(envPath, "utf-8");
  for (const line of envContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (!process.env[key]) process.env[key] = val;
  }
} catch {}

// ─── Configuration ────────────────────────────────────────────
const FEISHU_APP_ID = process.env.FEISHU_APP_ID;
const FEISHU_APP_SECRET = process.env.FEISHU_APP_SECRET;
const NANOBOT_URL = process.env.NANOBOT_URL || "http://localhost:8080";
const NANOBOT_AGENT_ID = process.env.NANOBOT_AGENT_ID || "assistant";
const BRIDGE_PORT = parseInt(process.env.BRIDGE_PORT || "3000", 10);
const FEISHU_ENCRYPT_KEY = process.env.FEISHU_ENCRYPT_KEY || "";

if (!FEISHU_APP_ID || !FEISHU_APP_SECRET) {
  console.error("ERROR: FEISHU_APP_ID and FEISHU_APP_SECRET are required");
  process.exit(1);
}

// ─── Feishu API Helpers ───────────────────────────────────────
const FEISHU_API = "https://open.feishu.cn/open-apis";

let tenantToken = "";
let tokenExpiry = 0;

async function getTenantToken() {
  if (tenantToken && Date.now() < tokenExpiry) return tenantToken;

  const resp = await fetch(
    `${FEISHU_API}/auth/v3/tenant_access_token/internal`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: FEISHU_APP_ID,
        app_secret: FEISHU_APP_SECRET,
      }),
    }
  );
  const data = await resp.json();
  if (data.code !== 0) {
    throw new Error(`Failed to get tenant token: ${JSON.stringify(data)}`);
  }
  tenantToken = data.tenant_access_token;
  // Expire 5 minutes early
  tokenExpiry = Date.now() + (data.expire - 300) * 1000;
  console.log("[feishu] Tenant token refreshed");
  return tenantToken;
}

async function sendFeishuMessage(chatId, text) {
  const token = await getTenantToken();
  const resp = await fetch(
    `${FEISHU_API}/im/v1/messages?receive_id_type=chat_id`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        receive_id: chatId,
        msg_type: "text",
        content: JSON.stringify({ text }),
      }),
    }
  );
  const data = await resp.json();
  if (data.code !== 0) {
    console.error("[feishu] Failed to send message:", JSON.stringify(data));
  }
  return data;
}

async function replyFeishuMessage(messageId, text) {
  const token = await getTenantToken();
  const resp = await fetch(
    `${FEISHU_API}/im/v1/messages/${messageId}/reply`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        msg_type: "text",
        content: JSON.stringify({ text }),
      }),
    }
  );
  const data = await resp.json();
  if (data.code !== 0) {
    console.error("[feishu] Failed to reply message:", JSON.stringify(data));
  }
  return data;
}

// ─── Decrypt helper (if encrypt key is set) ───────────────────
function decryptEvent(encrypt) {
  if (!FEISHU_ENCRYPT_KEY) return null;
  const key = crypto
    .createHash("sha256")
    .update(FEISHU_ENCRYPT_KEY)
    .digest();
  const encryptBuffer = Buffer.from(encrypt, "base64");
  const iv = encryptBuffer.subarray(0, 16);
  const cipherText = encryptBuffer.subarray(16);
  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  let decrypted = decipher.update(cipherText, undefined, "utf-8");
  decrypted += decipher.final("utf-8");
  // Remove random prefix (first 4 bytes length + random bytes)
  return JSON.parse(decrypted);
}

// ─── Nanobot MCP-UI Client ───────────────────────────────────
// Maps feishu chatId -> { sessionId, initialized }
const sessionMap = new Map();
let rpcId = 1;

function nextId() {
  return String(rpcId++);
}

async function nanobotRPC(method, params, sessionId) {
  const headers = { "Content-Type": "application/json" };
  if (sessionId) headers["Mcp-Session-Id"] = sessionId;

  const body = {
    jsonrpc: "2.0",
    id: nextId(),
    method,
    params: params || {},
  };

  const resp = await fetch(`${NANOBOT_URL}/mcp/ui`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  const newSessionId = resp.headers.get("mcp-session-id");
  const text = await resp.text();

  let result;
  try {
    result = JSON.parse(text);
  } catch {
    result = { raw: text };
  }

  return { result, sessionId: newSessionId || sessionId };
}

async function getOrCreateSession(chatId) {
  if (sessionMap.has(chatId)) {
    return sessionMap.get(chatId);
  }

  // Initialize MCP session
  const initResult = await nanobotRPC("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "feishu-bridge", version: "1.0.0" },
  });

  const sessionId = initResult.sessionId;
  if (!sessionId) {
    throw new Error("Failed to get session ID from nanobot");
  }

  // Send initialized notification
  await nanobotRPC("notifications/initialized", {}, sessionId);

  const session = { sessionId, initialized: true };
  sessionMap.set(chatId, session);
  console.log(`[nanobot] Session created for chat ${chatId}: ${sessionId}`);
  return session;
}

async function collectSSEResponse(sessionId) {
  return new Promise((resolve, reject) => {
    const url = `${NANOBOT_URL}/api/events/${sessionId}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
      resolve(textParts.join(""));
    }, 120000); // 2 minute timeout

    const textParts = [];
    let done = false;

    fetch(url, {
      headers: { Accept: "text/event-stream" },
      signal: controller.signal,
    })
      .then(async (resp) => {
        const reader = resp.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done: readerDone, value } = await reader.read();
          if (readerDone) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          let eventType = "";
          for (const line of lines) {
            if (line.startsWith("event:")) {
              eventType = line.slice(6).trim();
            } else if (line.startsWith("data:")) {
              const data = line.slice(5).trim();
              if (eventType === "chat-done" || eventType === "done") {
                done = true;
                clearTimeout(timeout);
                controller.abort();
                resolve(textParts.join(""));
                return;
              }
              if (data && eventType !== "history-start" && eventType !== "history-end" && eventType !== "chat-in-progress") {
                try {
                  const msg = JSON.parse(data);
                  if (msg.role === "assistant" && msg.items) {
                    for (const item of msg.items) {
                      if (item.content?.type === "text" && item.content?.text) {
                        textParts.push(item.content.text);
                      } else if (item.type === "text" && item.text) {
                        textParts.push(item.text);
                      }
                    }
                  }
                } catch {}
              }
            } else if (line === "") {
              eventType = "";
            }
          }
        }

        if (!done) {
          clearTimeout(timeout);
          resolve(textParts.join(""));
        }
      })
      .catch((err) => {
        clearTimeout(timeout);
        if (err.name === "AbortError") {
          resolve(textParts.join(""));
        } else {
          reject(err);
        }
      });
  });
}

async function sendToNanobot(chatId, userMessage) {
  const session = await getOrCreateSession(chatId);
  const toolName = `chat-with-${NANOBOT_AGENT_ID}`;

  // Start SSE listener before sending the message
  const responsePromise = collectSSEResponse(session.sessionId);

  // Send chat message via tools/call
  const callResult = await nanobotRPC(
    "tools/call",
    {
      name: toolName,
      arguments: { prompt: userMessage },
      _meta: {
        "ai.nanobot.async": true,
        progressToken: `msg-${Date.now()}`,
      },
    },
    session.sessionId
  );

  if (callResult.result?.error) {
    console.error("[nanobot] Tool call error:", callResult.result.error);
    // Session might be expired, recreate
    sessionMap.delete(chatId);
    throw new Error(
      callResult.result.error.message || "Tool call failed"
    );
  }

  // Wait for SSE response
  const response = await responsePromise;
  return response || "(no response)";
}

// ─── Dedup: prevent processing same event twice ──────────────
const processedEvents = new Set();
function isDuplicate(eventId) {
  if (!eventId) return false;
  if (processedEvents.has(eventId)) return true;
  processedEvents.add(eventId);
  // Clean up old events after 5 minutes
  setTimeout(() => processedEvents.delete(eventId), 300000);
  return false;
}

// ─── Express Server ──────────────────────────────────────────
const app = express();
app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", nanobot: NANOBOT_URL, agent: NANOBOT_AGENT_ID });
});

// Feishu webhook endpoint
app.post("/webhook/feishu", async (req, res) => {
  let body = req.body;

  // Handle encrypted events
  if (body.encrypt && FEISHU_ENCRYPT_KEY) {
    try {
      body = decryptEvent(body.encrypt);
    } catch (err) {
      console.error("[feishu] Decrypt failed:", err);
      return res.status(400).json({ error: "decrypt failed" });
    }
  }

  // Handle URL verification challenge
  if (body.type === "url_verification") {
    console.log("[feishu] URL verification challenge received");
    return res.json({ challenge: body.challenge });
  }

  // Handle event callback (v2.0 format)
  const schema = body.schema;
  const header = body.header;
  const event = body.event;

  if (!header || !event) {
    // Try v1.0 format
    if (body.event?.type === "message") {
      // V1.0 format handling would go here
      console.log("[feishu] V1.0 event format detected, please use V2.0");
      return res.json({ ok: true });
    }
    return res.json({ ok: true });
  }

  // Respond immediately to Feishu (they require fast response)
  res.json({ ok: true });

  // Deduplicate events
  const eventId = header.event_id;
  if (isDuplicate(eventId)) {
    console.log(`[feishu] Duplicate event ${eventId}, skipping`);
    return;
  }

  const eventType = header.event_type;

  if (eventType === "im.message.receive_v1") {
    const message = event.message;
    const chatId = message.chat_id;
    const messageId = message.message_id;
    const msgType = message.message_type;
    const sender = event.sender;

    // Skip bot's own messages
    if (sender?.sender_type === "app") return;

    // Only handle text messages for now
    if (msgType !== "text") {
      await replyFeishuMessage(messageId, "暂时只支持文字消息哦~");
      return;
    }

    let userText;
    try {
      const content = JSON.parse(message.content);
      userText = content.text;
    } catch {
      userText = message.content;
    }

    if (!userText) return;

    // Remove @bot mention prefix if present
    userText = userText.replace(/@_user_\d+\s*/g, "").trim();
    if (!userText) return;

    console.log(`[feishu] Message from ${chatId}: ${userText.slice(0, 50)}...`);

    try {
      const reply = await sendToNanobot(chatId, userText);
      await replyFeishuMessage(messageId, reply);
      console.log(`[feishu] Reply sent to ${chatId}: ${reply.slice(0, 50)}...`);
    } catch (err) {
      console.error(`[feishu] Error processing message:`, err);
      await replyFeishuMessage(
        messageId,
        `抱歉，处理消息时出错了: ${err.message}`
      );
    }
  }
});

// ─── Start ───────────────────────────────────────────────────
app.listen(BRIDGE_PORT, () => {
  console.log("╔══════════════════════════════════════════════╗");
  console.log("║     Nanobot Feishu Bridge                    ║");
  console.log("╠══════════════════════════════════════════════╣");
  console.log(`║  Bridge:  http://localhost:${BRIDGE_PORT}             ║`);
  console.log(`║  Webhook: http://localhost:${BRIDGE_PORT}/webhook/feishu ║`);
  console.log(`║  Nanobot: ${NANOBOT_URL.padEnd(34)}║`);
  console.log(`║  Agent:   ${NANOBOT_AGENT_ID.padEnd(34)}║`);
  console.log("╚══════════════════════════════════════════════╝");
  console.log("");
  console.log("飞书开放平台配置:");
  console.log(`  1. 事件订阅 URL: http://<你的公网地址>:${BRIDGE_PORT}/webhook/feishu`);
  console.log("  2. 添加事件: im.message.receive_v1 (接收消息)");
  console.log("  3. 机器人权限: im:message, im:message:send_as_bot");
  console.log("");
});
