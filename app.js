/* write your server code here */
const express = require('express');
const app = express();
const apirouter = require('./backEnd/routes/apirouter');
app.use(express.json());
app.use('/', apirouter);
module.exports = app;
