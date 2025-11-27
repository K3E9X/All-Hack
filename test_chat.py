#!/usr/bin/env python3
"""
Test script for Chat Interface

Tests WebSocket chat functionality.
"""
import asyncio
import websockets
import json
import sys

async def test_websocket_chat(scan_id: str):
    """Test WebSocket chat"""
    uri = f"ws://localhost:8000/ws/chat/{scan_id}"

    print(f"🔌 Connecting to {uri}...")

    try:
        async with websockets.connect(uri) as websocket:
            print("✅ Connected!")

            # Receive welcome message
            welcome = await websocket.recv()
            data = json.loads(welcome)
            print(f"\n{data.get('content')}\n")

            # Test questions
            questions = [
                "What are the critical vulnerabilities?",
                "How many vulnerabilities did you find?",
                "What should I fix first?",
            ]

            for question in questions:
                print(f"\n💬 User: {question}")

                # Send question
                await websocket.send(json.dumps({"message": question}))

                # Receive response
                print("🤖 Assistant: ", end="", flush=True)

                while True:
                    response = await websocket.recv()
                    data = json.loads(response)

                    if data.get("type") == "user":
                        continue  # Echo of our message

                    elif data.get("type") == "assistant_chunk":
                        print(data.get("content", ""), end="", flush=True)

                    elif data.get("type") == "assistant_complete":
                        print("\n")  # New line after complete response
                        break

                    elif data.get("type") == "error":
                        print(f"\n❌ Error: {data.get('content')}")
                        break

                await asyncio.sleep(1)  # Pause between questions

            print("\n✅ Chat test complete!")

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_chat.py <scan_id>")
        sys.exit(1)

    scan_id = sys.argv[1]
    asyncio.run(test_websocket_chat(scan_id))
