#!/bin/bash

# All-Hack Status Script
# Compatible: macOS, Debian, Ubuntu, Fedora

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo "All-Hack Status"
echo "==============="
echo ""

# Check backend
BACKEND_RUNNING=false
if pgrep -f "uvicorn app.main:app" > /dev/null 2>&1; then
    BACKEND_RUNNING=true
    BACKEND_PID=$(pgrep -f "uvicorn app.main:app" | head -1)
    echo -e "Backend:  ${GREEN}Running${NC} (PID: $BACKEND_PID)"

    # Try health check
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 http://localhost:8001/docs 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" == "200" ]; then
            echo -e "  Status: ${GREEN}Healthy${NC}"
        elif [ "$HTTP_CODE" == "000" ]; then
            echo -e "  Status: ${YELLOW}Starting...${NC}"
        else
            echo -e "  Status: ${YELLOW}HTTP $HTTP_CODE${NC}"
        fi
    fi
else
    echo -e "Backend:  ${RED}Stopped${NC}"
fi

# Check frontend dev server
FRONTEND_RUNNING=false
if pgrep -f "vite" > /dev/null 2>&1; then
    FRONTEND_RUNNING=true
    FRONTEND_PID=$(pgrep -f "vite" | head -1)
    echo -e "Frontend: ${GREEN}Running (dev)${NC} (PID: $FRONTEND_PID)"
else
    if [ "$BACKEND_RUNNING" = true ]; then
        echo -e "Frontend: ${BLUE}Served by backend${NC}"
    else
        echo -e "Frontend: ${RED}Stopped${NC}"
    fi
fi

# Show URLs
echo ""
echo "URLs:"
if [ "$BACKEND_RUNNING" = true ]; then
    if [ "$FRONTEND_RUNNING" = true ]; then
        echo "  Development: http://localhost:5173"
    fi
    echo "  Production:  http://localhost:8001"
    echo "  API Docs:    http://localhost:8001/docs"
else
    echo "  (Not running)"
fi

# Show logs location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "$SCRIPT_DIR/logs" ]; then
    echo ""
    echo "Logs:"
    echo "  $SCRIPT_DIR/logs/"
fi

echo ""
