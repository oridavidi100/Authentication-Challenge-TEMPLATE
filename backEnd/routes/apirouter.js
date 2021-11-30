const express = require('express');
const router = express.Router();
const { register } = require('../controlers/controoller');
router.post('/users/register', register);
module.exports = router;
