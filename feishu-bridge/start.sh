#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "╔══════════════════════════════════════════════╗"
echo "║   Nanobot + Feishu Bridge + Tunnel           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Load .env
set -a
source "$SCRIPT_DIR/.env"
set +a

NANOBOT_BIN="$PROJECT_DIR/bin/nanobot"
NANOBOT_CONFIG="$PROJECT_DIR/nanobot.yaml"
BRIDGE_PORT="${BRIDGE_PORT:-3000}"
PIDS=()

# Cleanup on exit
cleanup() {
  echo ""
  echo "Shutting down..."
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  echo "Done."
  exit 0
}
trap cleanup SIGINT SIGTERM

# Check prerequisites
if [ ! -f "$NANOBOT_BIN" ]; then
  echo "ERROR: nanobot binary not found at $NANOBOT_BIN"
  echo "Run 'make' in the project root first."
  exit 1
fi

if ! command -v cloudflared &>/dev/null; then
  echo "ERROR: cloudflared not found. Install with: brew install cloudflared"
  exit 1
fi

# Install bridge dependencies if needed
if [ ! -d "$SCRIPT_DIR/node_modules" ]; then
  echo "[0/3] Installing bridge dependencies..."
  cd "$SCRIPT_DIR" && npm install --silent
fi

# 1. Start nanobot
echo "[1/3] Starting nanobot..."
"$NANOBOT_BIN" run -c "$NANOBOT_CONFIG" -q &
PIDS+=($!)
echo "  PID: ${PIDS[-1]}"

echo "  Waiting for nanobot..."
for i in $(seq 1 30); do
  if curl -s -o /dev/null http://localhost:8080/mcp/ui -X POST \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"1","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"health","version":"1.0.0"}}}' 2>/dev/null; then
    echo "  Nanobot ready!"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "  ERROR: Nanobot failed to start"
    cleanup
  fi
  sleep 1
done

# 2. Start feishu bridge
echo "[2/3] Starting Feishu bridge..."
cd "$SCRIPT_DIR" && node bridge.mjs &
PIDS+=($!)
echo "  PID: ${PIDS[-1]}"
sleep 1

# 3. Start cloudflared tunnel
echo "[3/3] Starting cloudflared tunnel..."
TUNNEL_LOG=$(mktemp)
cloudflared tunnel --url "http://localhost:$BRIDGE_PORT" 2>"$TUNNEL_LOG" &
PIDS+=($!)
echo "  PID: ${PIDS[-1]}"

# Wait for tunnel URL
echo "  Waiting for tunnel URL..."
TUNNEL_URL=""
for i in $(seq 1 15); do
  TUNNEL_URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$TUNNEL_LOG" 2>/dev/null | head -1)
  if [ -n "$TUNNEL_URL" ]; then
    break
  fi
  sleep 1
done
rm -f "$TUNNEL_LOG"

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   All services running!                      ║"
echo "╠══════════════════════════════════════════════╣"
echo "║  Nanobot:  http://localhost:8080              ║"
echo "║  Bridge:   http://localhost:$BRIDGE_PORT              ║"
if [ -n "$TUNNEL_URL" ]; then
echo "║  Tunnel:   $TUNNEL_URL"
echo "╠══════════════════════════════════════════════╣"
echo "║                                              ║"
echo "║  飞书事件订阅 URL:                            ║"
echo "║  ${TUNNEL_URL}/webhook/feishu"
fi
echo "║                                              ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop all services."

# Wait for any child to exit
wait
