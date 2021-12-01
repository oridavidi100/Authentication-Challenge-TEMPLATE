const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

const {
  register,
  login,
  tokenValidate,
  information,
  token,
  logout,
  users,
  options,
} = require('../controlers/controoller');

//requset
router.post('/users/login', login);
router.post('/users/register', register);
router.post('/users/tokenValidate', tokenValidate);
router.get('/api/v1/information', information);
router.post('/users/token', token);
router.post('/users/logout', logout);
router.get('/api/v1/users', users);
router.options('/', options);
module.exports = router;
