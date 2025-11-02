#!/bin/bash

echo "🚀 Starting Advanced Pentest Tool..."
echo ""

# Check if backend venv exists
if [ ! -d "backend/venv" ]; then
    echo "❌ Backend virtual environment not found. Please run:"
    echo "   cd backend && python -m venv venv && pip install -r requirements.txt"
    exit 1
fi

# Check if frontend node_modules exists
if [ ! -d "frontend/node_modules" ]; then
    echo "❌ Frontend dependencies not found. Please run:"
    echo "   cd frontend && npm install"
    exit 1
fi

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Stopping services..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start backend
echo "🔧 Starting backend on http://localhost:8001..."
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 > /tmp/pentest-backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait a bit for backend to start
sleep 3

# Start frontend
echo "🎨 Starting frontend on http://localhost:5173..."
cd frontend
npm run dev > /tmp/pentest-frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

echo ""
echo "✅ Services started successfully!"
echo ""
echo "📍 Backend API: http://localhost:8001"
echo "📍 Frontend UI: http://localhost:5173"
echo "📍 API Docs: http://localhost:8001/docs"
echo ""
echo "📋 Logs:"
echo "   Backend: tail -f /tmp/pentest-backend.log"
echo "   Frontend: tail -f /tmp/pentest-frontend.log"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for processes
wait $BACKEND_PID $FRONTEND_PID
