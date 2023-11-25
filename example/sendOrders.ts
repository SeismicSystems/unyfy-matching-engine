// sendOrders.ts
import WebSocket from 'ws';
import * as fs from 'fs';
import * as crypto from 'crypto';

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();
const rawOrders = fs.readFileSync('sendorders.txt', 'utf8').split('--');
const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

let constructedOrders = '';

ws.on('open', function open() {
    console.log('Connected to the server!');

    rawOrders.forEach(order => {
        const lines = order.trim().split('\n');
        const priceLine = lines.find(line => line.startsWith('price'));
        const volumeLine = lines.find(line => line.startsWith('volume'));
        const sideLine = lines.find(line => line.startsWith('side'));
    
        const orderData = {
            price: priceLine ? priceLine.split('=')[1].trim() : undefined,
            volume: volumeLine ? volumeLine.split('=')[1].trim() : undefined,
            side: sideLine ? sideLine.split('=')[1].trim() : undefined,
            accessKey: parseInt(crypto.randomBytes(5).toString('hex'), 16),
        };



        const hash = crypto.createHash('sha256');
if (orderData.price) hash.update(orderData.price);
if (orderData.volume) hash.update(orderData.volume);
if (orderData.accessKey) hash.update(orderData.accessKey.toString());
const hashValue = hash.digest('hex').slice(0, 30); // First 30 bytes of the hash

        constructedOrders += `price = ${orderData.price}\nvolume = ${orderData.volume}\nside = ${orderData.side}\naccess_key = ${orderData.accessKey}\nhash = ${hashValue}\n--\n`;
        const sendOrderRequestJson = {
            "action": "sendorder",
            "data": {
                "transparent": {
                    "side": orderData.side?.toString(),
                    "token": "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65",
                    "denomination": "0x1"
                },
                "shielded": {
                    "price": (parseFloat(orderData.price || '0') * 10**9).toString(),
                    "volume": (parseInt(orderData.volume || '0') * 10**9).toString(),
                    "accessKey": orderData.accessKey.toString()
                }
            },
            "hash": hashValue.toString()
        };

        console.log(sendOrderRequestJson);

        ws.send(JSON.stringify(sendOrderRequestJson), (error) => {
            if (error) {
                console.error('Error sending message:', error);
            }
        });
    });

    fs.writeFileSync('constructedorders.txt', constructedOrders.trim());
    console.log('Constructed orders written to constructedorders.txt');
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
