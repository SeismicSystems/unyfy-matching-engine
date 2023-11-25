// getCrossedOrders.ts
import WebSocket from 'ws';
import * as fs from 'fs';

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();
const orderLines = fs.readFileSync('getcrossedorders.txt', 'utf8').trim().split('\n');

const orderDetails = {
    price: orderLines[0].split('=')[1].trim(),
    volume: orderLines[1].split('=')[1].trim(),
    side: orderLines[2].split('=')[1].trim(),
    access_key: orderLines[3].split('=')[1].trim(),
    hash: orderLines[4].split('=')[1].trim(),
};

const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

ws.on('open', function open() {
    console.log('Connected to the server!');

    const getCrossedOrdersRequestJson = {
        "action": "getcrossedorders",
        "data": {
            "transparent": {
                "side": orderDetails.side.toString(),
                "token": "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65",
                "denomination": "0x1"
            },
            "shielded": {
                "price": (parseFloat(orderDetails.price || '0') * 10**9).toString(),
                "volume": (parseInt(orderDetails.volume || '0') * 10**9).toString(),
                "accessKey": orderDetails.access_key.toString(),
                "hash": orderDetails.hash.toString()
            }
        }
    };

    ws.send(JSON.stringify(getCrossedOrdersRequestJson), (error) => {
        if (error) {
            console.error('Error sending get crossed orders message:', error);
        }
    });
});

ws.on('message', function message(data) {
    console.log('Received message:', data.toString());
});

ws.on('error', function error(err) {
    console.error('WebSocket error:', err);
});

ws.on('close', function close() {
    console.log('WebSocket connection closed');
});
