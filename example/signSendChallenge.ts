// signSendChallenge.ts
import axios from 'axios';
import { Wallet } from 'ethers';
import * as fs from 'fs';

const envData = fs.readFileSync('.env', 'utf8');
const privateKey = envData.split('\n')[0].split('=')[1];
// console.log(privateKey);
const wallet = new Wallet(privateKey);

const challenge = fs.readFileSync('challenge.txt', 'utf8');
wallet.signMessage(challenge).then(signature => {
  axios.post('http://localhost:8000/submit_response', {
    challenge_id: challenge,
    signature: signature,
    pub_key: wallet.address
  })
  .then(response => {
    fs.writeFileSync('jwt.txt', response.data);
    console.log('JWT received and stored in jwt.txt');
  })
  .catch(error => console.error(error));
}); 