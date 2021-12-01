const express = require('express');
const router = express.Router();
const { register, login, authentication, information, token, logout, users } = require('../controlers/controoller');

//requset
router.post('/users/login', login);
router.post('/users/register', register);
router.post('/users/tokenValidate', authentication);
router.get('/api/v1/information', information);
router.post('/users/token', token);
router.post('/users/logout', logout);
router.get('/api/v1/users', users);
router.options('/', (req, res, next) => {});
module.exports = router;
