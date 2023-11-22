import { ethers } from 'ethers';
import axios from 'axios';  
import WebSocket from 'ws';

//sample order data -- adjust as per need
const sendorderrequestJson = {
    "action": "sendorder",
    "data": {
      "transparent": {
        "side": "1",
        "token": "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65",
        "denomination": "0x1"
      },
      "shielded": {
        "price": "99331421600",
        "volume": "3000000000",
        "accessKey": "1"
      }
    },
    "hash": "1303177350543915549821791317173867930338436297750196254712378410446088378"
  };
  
  
  const getcrossedordersrequestJson = {
    "action": "getcrossedorders",
    "data": {
      "transparent": {
        "side": "1",
        "token": "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65",
        "denomination": "0x1"
      },
      "shielded": {
        "price": "99331421600",
        "volume": "3000000000",
        "accessKey": "1"
      }
    },
    "hash": "1303177350543915549821791317173867930338436297750196254712378410446088378"
  };
  
// Generate a random private key
let privateKey = ethers.Wallet.createRandom().privateKey;
// Compute the corresponding public address
let wallet = new ethers.Wallet(privateKey);
let address = wallet.address;
console.log("The wallet address is: ", address);

// Send a post request to localhost:8000/request_challenge

axios.post('http://localhost:8000/request_challenge')
.then(function (response) {
    // console.log(response);
    // Convert the response to a string
    let responseString = response.data;
    console.log("The message to be signed is:", responseString);
    // Sign the response string
    wallet.signMessage(responseString).then((signature) => {
        console.log("The message has been signed with the signature: ", signature);
        console.log("Sending signature to server for verification and JWT issuance...");
        // Send the response, signature and public address back to localhost:8000/submit_response
        axios.post('http://localhost:8000/submit_response', {
            "challenge_id": responseString,
            "signature": signature,
            "pub_key": address
        })
        .then(function (response) {
           // console.log(response);
           let responseString = response.data;
            console.log("The obtained JWT is: ", responseString);
            // Open a WebSocket connection with the "authorization" header and "bearer <response string>"
            const headers = {
                'Authorization': 'Bearer ' + responseString
            };
            console.log("Opening WebSocket connection...");
            const ws = new WebSocket('ws://localhost:8000/ws', { headers });
            ws.on('open', function open() {
                console.log('Connected to the server!');
                // Send the request when the connection is opened
                ws.send(JSON.stringify(sendorderrequestJson), (error) => {
                  if (error) {
                    console.log('Error sending message:', error);
                  }
                });
              
                setTimeout(() => {
                  ws.send(JSON.stringify(getcrossedordersrequestJson), (error) => {
                    if (error) {
                      console.log('Error sending message:', error);
                    }
                  });
                }, 5000);
              
              
              });
              
              // Listen for messages from the server
              
              ws.on('message', function(data) {
                if (data instanceof Buffer) {
                  // Convert Buffer to string
                  const message = data.toString('utf-8');
                  console.log('Received a message from the server:', message);
                } else {
                  // It's already a string
                  console.log('Received a message from the server:', data);
                }
              });
              
              
              
              // Error event
              ws.on('error', function error(error) {
                console.log('WebSocket error:', error);
              });
              
              // Close event
              ws.on('close', function close(code, reason) {
                console.log(`WebSocket closed with code: ${code} and reason: ${reason}`);
              });


        })
        .catch(function (error) {
            console.log(error);
        });
    });
})
.catch(function (error) {
    console.log(error);
});

