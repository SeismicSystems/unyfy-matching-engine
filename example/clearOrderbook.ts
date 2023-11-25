// clearOrderbook.ts
import WebSocket from 'ws';
import * as fs from 'fs';

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();
const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

ws.on('open', function open() {
    console.log('Connected to the server!');

    const clearOrderbookRequestJson = {
        "action": "clearorderbook"
    };

    ws.send(JSON.stringify(clearOrderbookRequestJson), (error) => {
        if (error) {
            console.error('Error sending clear orderbook message:', error);
        } else {
            console.log('Clear orderbook request sent.');
        }
     //   ws.close();
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
