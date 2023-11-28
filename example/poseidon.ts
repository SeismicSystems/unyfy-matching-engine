// @ts-ignore
import {poseidon} from 'circomlib';
const buildPoseidon = require("circomlibjs").buildPoseidon;
// pass an array to the function
// array length must be equal to the function name
// returns a BigInt
(async () => {
    const poseidon = await buildPoseidon();
    const hash = poseidon([1, 2, 3, 4, 5]);
    console.log(hash);
  })();