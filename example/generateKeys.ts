// generateKeys.ts
import { Wallet } from 'ethers';
import * as fs from 'fs';

const wallet = Wallet.createRandom();
const privateKey = wallet.privateKey;
const address = wallet.address;

const data = `PRIVATE_KEY=${privateKey}\nPUBLIC_KEY=${address}`;
fs.writeFileSync('.env', data);
console.log('Keys generated and stored in .env file');