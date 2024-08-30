import asyncio
import logging
import websockets

from datetime import datetime
from ocpp.routing import on
from ocpp.v16 import call
from ocpp.v16 import ChargePoint as cp
from ocpp.v16 import call_result
from ocpp.v16.enums import Action, RegistrationStatus

logging.basicConfig(filename='auto_app2.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class ChargePoint(cp):
    connected_charge_points = {}
    
    @on(Action.BootNotification)
    def on_boot_notification(
        self, charge_point_vendor: str, charge_point_model: str, **kwargs):
        return call_result.BootNotificationPayload(
            current_time=datetime.utcnow().isoformat(),
            interval=5,
            status=RegistrationStatus.accepted,
        )
        
    @on(Action.Heartbeat)
    def on_heartbeat(self):
        print("Got a Heartbeat!")
        return call_result.HeartbeatPayload(
            current_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        )
        
    # Tags valid for authorization
    AUTHORIZED_TAGS = ['user123', 'user456']
    
    @on(Action.Authorize)
    def on_authorize(self, id_tag):
        if id_tag in self.AUTHORIZED_TAGS:
            print(f"Authorization accepted for id_tag: {id_tag}")
            return call_result.AuthorizePayload(
                id_tag_info={'status': 'Accepted'}
            )
        else:
            print(f"Authorization denied for id_tag: {id_tag}")
            return call_result.AuthorizePayload(
                id_tag_info={'status': 'Blocked'}
            )
        
    # Class-level variable to keep track of transaction_id
    transaction_id_counter = 1
    
    @classmethod
    def get_next_transaction_id(cls):
        """Get the next transaction_id and increment the counter."""
        transaction_id = cls.transaction_id_counter
        cls.transaction_id_counter += 1
        return transaction_id
    
    active_transactions = {}
    
    @classmethod
    def start_transaction(cls, charge_point, connector_id, id_tag, meter_start, timestamp):
        transaction_id = cls.get_next_transaction_id()
        print(f"Start transaction for id_tag: {id_tag}, transaction_id: {transaction_id}")
        cls.active_transactions[transaction_id] = charge_point
        return transaction_id
    
    @classmethod
    def stop_transaction(cls, transaction_id, meter_stop, timestamp):
        if transaction_id in cls.active_transactions:
            charge_point = cls.active_transactions.pop(transaction_id)
            print(f"Stop transaction for transaction_id: {transaction_id}")
            charge_point.handle_stopped_transaction(transaction_id, meter_stop, timestamp)
            
    @on(Action.StartTransaction)
    def on_start_transaction(self, connector_id, id_tag, meter_start, timestamp):
        transaction_id = self.start_transaction(self, connector_id, id_tag, meter_start, timestamp)
        return call_result.StartTransactionPayload(
            transaction_id=transaction_id,
            id_tag_info={'status': 'Accepted'}
        )
        
    @on(Action.StopTransaction)
    def on_stop_transaction(self, transaction_id, meter_stop, timestamp):
        self.stop_transaction(transaction_id, meter_stop, timestamp)
        print(f"{self._unique_id_generator}")
        return call_result.StopTransactionPayload(
            id_tag_info={'status': 'Accepted'}
        )   
        
    @on(Action.RemoteStartTransaction)
    def on_remote_start_transaction(self, connector_id, id_tag):
        return call_result.RemoteStartTransactionPayload(
            status="Accepted"
        )
    
    @on(Action.RemoteStopTransaction)
    def on_remote_stop_transaction(self, transaction_id):
        return call_result.RemoteStopTransactionPayload(
            status="Accepted"
        )
    
    @on(Action.StatusNotification)
    def on_status_notification(self, connector_id, status, error_code=None, info=None, timestamp=None):
        """Handle incoming Status Notification messages from the charging station."""
        print(f"Received Status Notification for connector {connector_id}: Status - {status}")
        
        if status == 'Charging':
            # Add logic for when a connector starts charging
            pass
        elif status == 'Available':
            # Add logic for when a connector becomes available
            pass
        elif status == 'Faulted':
            # Add logic for handling fault status
            pass
        
        return call_result.StatusNotificationPayload(status='Accepted')
    
    async def send_remote_start_transaction(charge_point_id, id_tag, connector_id):
        async with websockets.connect(
            "ws://arsek-ws.duckdns.org:8765/{charge_point_id}".format(charge_point_id=charge_point_id)
        ) as ws:
            request = cp.on_remote_start_transaction(
                id_tag=id_tag,
                connector_id=connector_id,
            )
            response = await ws.send(request)

            print(f"RemoteStartTransaction response received: {response}")
    
    def handle_stopped_transaction(self, transaction_id, meter_stop, timestamp):
        # Perform any additional logic when a transaction is stopped
        # Example: Send a message, update a database, etc.
        print(f"Handling stopped transaction for transaction_id: {transaction_id}, meter_stop: {meter_stop}")

    async def remote_start_transaction(self, connector_id, id_tag):
        request = call.RemoteStartTransactionPayload(
                connector_id=connector_id, id_tag=id_tag
        )
        await self.call(request)

    async def remote_stop_transaction(self, transaction_id):
        request = call.RemoteStopTransactionPayload(
                transaction_id=transaction_id
        )
        await self.call(request)

async def on_connect(websocket, path):
    """For every new charge point that connects, create a ChargePoint
    instance and start listening for messages."""
    try:
        requested_protocols = websocket.request_headers["Sec-WebSocket-Protocol"]
        logging.info("Requested Protocols: %s", requested_protocols)
    except KeyError:
        logging.error("Client hasn't requested any Subprotocol. Closing Connection")
        return await websocket.close()
    if websocket.subprotocol:
        logging.info("Protocols Matched: %s", websocket.subprotocol)
    else:
        # In the websockets lib if no subprotocols are supported by the
        # client and the server, it proceeds without a subprotocol,
        # so we have to manually close the connection.
        logging.warning(
            "Protocols Mismatched | Expected Subprotocols: %s,"
            " but client supports  %s | Closing connection",
            websocket.available_subprotocols,
            requested_protocols,
        )
        return await websocket.close()

    charge_point_id = path.strip("/")
    cp_instance = ChargePoint(charge_point_id, websocket)

    ChargePoint.connected_charge_points[charge_point_id] = cp_instance
    logging.info("Connected Charge Points: %s", list(ChargePoint.connected_charge_points.keys()))

    # await asyncio.sleep(60)
    # asyncio.create_task(cp_instance.remote_start_transaction(1, "user123"))

    await cp_instance.start()

async def main():
    server = await websockets.serve(
        on_connect, "192.168.27.10", 8765, subprotocols=["ocpp1.6"], ping_timeout=None
    )
    logging.info("Server Started listening to new connections...")
    
    # charge_point_instance = ChargePoint('CP_1', None)

    # asyncio.create_task(
    #     charge_point_instance.send_remote_start_transaction(
    #         id_tag='user123', connector_id=1
    #     )
    # )

    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
