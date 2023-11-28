// sendOrders.ts
import WebSocket from 'ws';
import * as fs from 'fs';
import * as crypto from 'crypto';
const buildPoseidon = require("circomlibjs").buildPoseidon;

const jwt = fs.readFileSync('jwt.txt', 'utf8').trim();
const rawOrders = fs.readFileSync('sendorders.txt', 'utf8').split('--');
const ws = new WebSocket('ws://localhost:8000/ws', {
    headers: { Authorization: `Bearer ${jwt}` }
});

let constructedOrders = '';

async function getPoseidonHash(price: String, volume: String, side: String, accessKey: String) {
    const poseidon = await buildPoseidon();
    return poseidon([price, volume, side, accessKey]);
}


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
            accessKey: crypto.randomBytes(31).toString('hex'),
        };

        let hexstring=orderData.accessKey.toString();
        let bigInt = BigInt('0x'+hexstring);
        let bigIntString = bigInt.toString();


            let price = parseFloat(orderData.price || '0')*10**9;
            let volume = parseInt(orderData.volume || '0')*10**9;
            let side =  orderData.side?.toString() || '0';
            let buffer = orderData.accessKey ? Buffer.from(orderData.accessKey, 'hex') : Buffer.alloc(0);
            getPoseidonHash(price.toString(), volume.toString(), side, bigIntString).then((hash) => {
                console.log(hash.toString)
                let hashString = hash.toString();
                let decimalArray = hashString.split(",");
                let hexArray = decimalArray.map((num: string) => parseInt(num).toString(16).padStart(2, '0'));
let hexString = hexArray.join("");
console.log(hexString); // Outputs the hexadecimal string
                constructedOrders += `price = ${orderData.price}\nvolume = ${orderData.volume}\nside = ${orderData.side}\naccess_key = ${orderData.accessKey}\nhash = ${hash}\n--\n`;
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
                    "hash": hexString
                };
        
                console.log(sendOrderRequestJson);
        
                ws.send(JSON.stringify(sendOrderRequestJson), (error) => {
                    if (error) {
                        console.error('Error sending message:', error);
                    }
                });
            });
        })
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

