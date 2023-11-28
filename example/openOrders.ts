
import WebSocket from 'ws';
import * as fs from 'fs';

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();

const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

ws.on('open', function open() {
    console.log('Connected to the server!');

    const openOrdersRequestJson = {
        "action": "openorders"
    };

    ws.send(JSON.stringify(openOrdersRequestJson), (error) => {
        if (error) {
            console.error('Error sending open orders message:', error);
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
