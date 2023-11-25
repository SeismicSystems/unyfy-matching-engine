// requestChallenge.ts
import axios from 'axios';
import * as fs from 'fs';

axios.post('http://localhost:8000/request_challenge')
  .then(response => {
    fs.writeFileSync('challenge.txt', response.data);
    console.log('Challenge received and stored in challenge.txt');
  })
  .catch(error => console.error(error));
