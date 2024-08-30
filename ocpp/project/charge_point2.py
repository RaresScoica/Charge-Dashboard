import asyncio
import logging
import websockets
import datetime
import json
import sys, os

from aio_pika import connect
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call
from ocpp.v16.enums import RegistrationStatus

logging.basicConfig(level=logging.INFO)

class ChargePoint(cp):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.keep_heartbeat_running = True
        self.heartbeat_task = None
        self.authorization_accepted = False
        
    async def send_boot_notification(self):
        request = call.BootNotificationPayload(
            charge_point_model="C6EU", charge_point_vendor="XCharge"
        )
        response = await self.call(request)

        if response.status == RegistrationStatus.accepted:
            print("Connected to central system.")
            await self.send_heartbeat(response.interval)
            
    async def send_heartbeat(self, interval):
        try:
            while self.keep_heartbeat_running:
                request = call.HeartbeatPayload()
                await self.call(request)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass
            
    def start_heartbeat(self, interval):
        self.keep_heartbeat_running = True
        self.heartbeat_task = asyncio.create_task(self.send_heartbeat(interval))        
    
    def stop_heartbeat(self):
        self.keep_heartbeat_running = False
        if self.heartbeat_task:
            self.heartbeat_task.cancel()

    async def send_authorization_check(self, id_tag):
        request = call.AuthorizePayload(
            id_tag=id_tag
        )
        response = await self.call(request)
        if response.id_tag_info['status'] == 'Accepted':
            self.authorization_accepted = True
        else:
            self.authorization_accepted = False
    
    # Timestamp
    current_timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            
    async def start_transaction(self, connector_id, meter_start, id_tag):
        if self.authorization_accepted:
            request = call.StartTransactionPayload(
                connector_id=connector_id, meter_start=meter_start, id_tag=id_tag, 
                timestamp=self.current_timestamp
            )
            await self.call(request)
        else:
            print(" Authorization not accepted. Cannot start transaction.")

    async def stop_transaction(self, transaction_id, meter_stop):
        request = call.StopTransactionPayload(
            transaction_id=transaction_id, meter_stop=meter_stop, 
            timestamp=self.current_timestamp
        )
        await self.call(request)

async def main():
    connection = await connect("amqp://guest:guest@localhost/")
    channel = await connection.channel()

    queue = await channel.declare_queue('charge_point_queue_CP_2')
    
    device_id = "CP_2"
    async with websockets.connect(
        f"ws://arsek-ws.duckdns.org:8765/{device_id}", subprotocols=["ocpp1.6"]
    ) as ws:
        charge_point = ChargePoint("CP_2", ws)
        
        asyncio.create_task(charge_point.start())
        
        # Start listening for RabbitMQ messages in a separate thread
        # asyncio.create_task(receive_messages_from_rabbitmq(queue, charge_point))
        
        while True:
            await asyncio.sleep(10)

async def receive_messages_from_rabbitmq(queue, charge_point):
    async for message in queue:
        try:
            message_body = json.loads(message.body.decode("utf-8"))
            print(f" Received message: {message_body}")
            message_type = message_body.get("type")

            if message_type == "boot_notification":
                asyncio.create_task(charge_point.send_boot_notification())
                
            elif message_type == "send_heartbeat":
                charge_point.start_heartbeat(interval=5)
                
            elif message_type == "stop_heartbeat":
                charge_point.stop_heartbeat()
                
            elif message_type == "authorization":
                id_tag = message_body.get("id_tag")
                asyncio.create_task(charge_point.send_authorization_check(id_tag))
                
            elif message_type == "start_transaction":
                connector_id = message_body.get("connector_id")
                meter_start = message_body.get("meter_start")
                id_tag = message_body.get("id_tag")
                asyncio.create_task(
                    charge_point.start_transaction(connector_id, meter_start, id_tag))
                
            elif message_type == "stop_transaction":
                transaction_id = message_body.get("transaction_id")
                meter_stop = message_body.get("meter_stop")
                asyncio.create_task(
                    charge_point.stop_transaction(transaction_id, meter_stop))
                
            else:
                print(f"Unhandled message type: {message_type}")

            await message.ack()
            
        except json.decoder.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)