import { ethers } from 'ethers';

// Generate a random private key
let privateKey = ethers.Wallet.createRandom().privateKey;
console.log("Private Key: ", privateKey);

// Compute the corresponding public key
let wallet = new ethers.Wallet(privateKey);
let address = wallet.address;
console.log("Private Key: ", privateKey);

// Sign a message
let message = "0xdf05cfc103f22b0127c4a82c02f62f89af44c69263722bc3bc4999cc627e4857";
console.log("Message: ", message);
wallet.signMessage(message).then((signature) => {
    console.log("Signature: ", signature);
  });

// Compute the address from the public key
console.log("Public Address: ", address);
