#!/bin/bash
#
# All-Hack Setup Script
# One-command installation for the pentest framework
#

set -e

echo "================================================"
echo "   ALL-HACK - Setup Script"
echo "   Advanced Penetration Testing Framework"
echo "================================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python
echo -e "${YELLOW}[1/5] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.9-3.12${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}  Found Python $PYTHON_VERSION${NC}"

# Check Node.js
echo -e "${YELLOW}[2/5] Checking Node.js...${NC}"
if ! command -v node &> /dev/null; then
    echo -e "${RED}Node.js is not installed. Please install Node.js 18+${NC}"
    exit 1
fi
NODE_VERSION=$(node -v)
echo -e "${GREEN}  Found Node.js $NODE_VERSION${NC}"

# Setup Backend
echo -e "${YELLOW}[3/5] Setting up backend...${NC}"
cd backend

if [ ! -d "venv" ]; then
    echo "  Creating virtual environment..."
    python3 -m venv venv
fi

echo "  Activating virtual environment..."
source venv/bin/activate

echo "  Upgrading pip..."
pip install --upgrade pip -q

echo "  Installing dependencies..."
pip install -r requirements.txt -q

if [ ! -f ".env" ]; then
    echo "  Creating .env file..."
    cp .env.example .env
fi

echo -e "${GREEN}  Backend setup complete!${NC}"
cd ..

# Setup Frontend
echo -e "${YELLOW}[4/5] Setting up frontend...${NC}"
cd frontend

echo "  Installing npm packages..."
npm install --silent

if [ ! -f ".env" ]; then
    echo "  Creating .env file..."
    cp .env.example .env
fi

echo "  Building for production..."
npm run build --silent

echo -e "${GREEN}  Frontend setup complete!${NC}"
cd ..

# Done
echo ""
echo -e "${YELLOW}[5/5] Setup complete!${NC}"
echo ""
echo "================================================"
echo -e "${GREEN}  ALL-HACK is ready!${NC}"
echo "================================================"
echo ""
echo "To start the application:"
echo ""
echo "  cd backend"
echo "  source venv/bin/activate"
echo "  uvicorn app.main:app --host 0.0.0.0 --port 8001"
echo ""
echo "Then open: http://localhost:8001"
echo ""
echo "================================================"
