import WebSocket from 'ws';
import * as fs from 'fs';

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();
const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

ws.on('open', function open() {
    console.log('Connected to the server!');

    const requestJson = {
        "action": "fillorders",
        "data": {
            "side": "1",
            "hash_own": "d1a98aece1ab79457a3cef2a6417d2",
            "hash_matched": ["4a43eaef5dec164d39c54fa59e113a"]
        }
    };

    ws.send(JSON.stringify(requestJson), (error) => {
        if (error) {
            console.error('Error sending fill orders message:', error);
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

