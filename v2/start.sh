#!/usr/bin/env bash
# start.sh - start the stack in the background and print access info.
#
# Usage:
#   ./start.sh            # start detached
#   ./start.sh --logs     # start detached and follow logs
#   ./start.sh stop       # stop and remove containers
#   ./start.sh restart    # restart cleanly

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { printf '[start] %s\n' "$*"; }
fail() { printf '[start] ERROR: %s\n' "$*" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    fail "Docker Compose not found. Run ./install.sh first."
fi

if [ ! -f .env ]; then
    fail ".env not found. Run ./install.sh first."
fi

case "${1:-up}" in
    stop)
        log "Stopping stack..."
        $COMPOSE_CMD down
        exit 0
        ;;
    restart)
        log "Restarting stack..."
        $COMPOSE_CMD down
        $COMPOSE_CMD up -d
        ;;
    up|--logs|"")
        log "Starting stack..."
        $COMPOSE_CMD up -d
        ;;
    *)
        fail "Unknown command: ${1}. Use: up | stop | restart | --logs"
        ;;
esac

printf '\n'
log "Stack is up."
log "  UI:         http://localhost:3000"
log "  API:        http://localhost:8000"
log "  API docs:   http://localhost:8000/docs"
log "  MITM proxy: http://localhost:8080  (set this as your browser HTTP/HTTPS proxy)"
printf '\n'

if [ "${1:-}" = "--logs" ]; then
    log "Following logs (Ctrl+C to detach, stack keeps running)..."
    $COMPOSE_CMD logs -f
fi
