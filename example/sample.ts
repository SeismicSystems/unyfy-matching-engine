import WebSocket from 'ws';

// Define the WebSocket server endpoint
const websocketServerUrl = 'ws://35.172.200.175:8000/ws';

// Create a new WebSocket connection
const ws = new WebSocket(websocketServerUrl);


const sendorderrequestJson = {
  "action": "sendorder",
  "data": {
    "transparent": {
      "side": "1",
      "token": "92bf259f558808106e4840e2642352b156a31bc41e5b4283df2937278f0a7a65",
      "denomination": "0x1"
    },
    "shielded": {
      "price": "100331421600",
      "volume": "1600000000",
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
      "price": "100331421600",
      "volume": "1600000000",
      "accessKey": "1"
    }
  },
  "hash": "1303177350543915549821791317173867930338436297750196254712378410446088378"
};

// Open connection event
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