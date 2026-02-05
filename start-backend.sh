#!/bin/bash

echo "🚀 Starting Advanced Pentest Tool - Backend"
echo "==========================================="

cd backend

# Check if venv exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Creating virtual environment..."
    python3 -m venv venv

    echo "Installing dependencies..."
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo ""
echo "✅ Backend starting on http://localhost:8001"
echo "📚 API docs available at http://localhost:8001/docs"
echo ""

uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
