import asyncio
import websockets

async def upload_firmware():
    uri = "ws://arsek-ws.duckdns.org:8765/firmware"
    try:
        async with websockets.connect(uri) as websocket:
            with open("C:/Users/developer/Documents/ws-server/xchargerNew.apk", 'rb') as file:
                while chunk := file.read(1024):
                    await websocket.send(chunk)
            print("File uploaded successfully")
    except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.ConnectionClosedOK) as e:
        print(f"WebSocket connection error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

asyncio.run(upload_firmware())
