#!/bin/bash

echo "🎨 Starting Advanced Pentest Tool - Frontend"
echo "==========================================="

cd frontend

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "❌ node_modules not found!"
    echo "Installing dependencies..."
    npm install
fi

echo ""
echo "✅ Frontend starting on http://localhost:5173"
echo ""

npm run dev
