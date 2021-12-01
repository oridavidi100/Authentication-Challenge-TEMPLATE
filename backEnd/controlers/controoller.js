const USERS = []; // [...{email, name, password, isAdmin}...]
const INFORMATION = []; // [...{email, info}...]
// const REFRESHTOKENS = [];
const jwt = require('jsonwebtoken');
require('dotenv').config();
const SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESHTOKENS = [];
const bcrypt = require('bcrypt');
// const salt = 10;

exports.register = async (req, res, next) => {
  const { email, user } = req.body;
  let { password } = req.body;
  let isAdmin = false;
  if (password === 'Rc123456!') {
    isAdmin = true;
  }
  const salt = await bcrypt.genSalt(10);
  password = await bcrypt.hash(password, salt);
  for (let user of USERS) {
    if (user.email === email) {
      return res.status(409).send('user already exists');
    }
  }
  USERS.push({ email: email, name: user, password: password, isAdmin: isAdmin });
  INFORMATION.push({ email: email, info: `${user} info` });
  res.status(201).send('Register Success');
  console.log(USERS, INFORMATION);
  next();
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  const body = {};
  let flag = 0;
  for (let user1 of USERS) {
    let ans = await bcrypt.compare(password, user1.password);
    console.log(ans);
    if (email === user1.email && ans) {
      body.email = user1.email;
      body.name = user1.name;
      body.isAdmin = user1.isAdmin;
      username = { email: email, password: password };
      const accessToken = jwt.sign(username, SECRET, { expiresIn: '70s' });
      body.accessToken = accessToken;
      body.refreshToken = jwt.sign(username, process.env.REFRESH_TOKEN_SECRET);
      if (!REFRESHTOKENS.includes(body.refreshToken)) {
        REFRESHTOKENS.push(body.refreshToken);
      }
      return res.status(200).send(body);
    } else if (email === user1.email || password === user1.password) {
      flag = 1;
    }
  }

  if (flag === 0) {
    return res.status(404).send('cannot find user');
  } else if (flag === 1) {
    return res.status(403).send('User or Password incorrect');
  }

  next();
};

exports.authentication = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  console.log(authHeader);
  const token = authHeader && authHeader.split(' ')[1];
  if (token === null) {
    return res.status(401).send('Access Token Required');
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Access Token');
    }
    const body = { valid: true };
    res.status(200).send(body);
    next();
  });
};
exports.information = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  console.log(authHeader);
  const token = authHeader && authHeader.split(' ')[1];
  if (token === null) {
    return res.status(401).send('Access Token Required');
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Access Token');
    }
    const body = {};
    for (let info of INFORMATION) {
      if (info.email === user.email) {
        body.email = user.email;
        body.info = info.info;
      }
    }
    res.status(200).send(body);
    next();
  });
};

exports.token = (req, res, next) => {
  const refreshToken = req.body.token;
  if (refreshToken === null) {
    return res.status(401).send('Refresh Token Required');
  }
  if (!REFRESHTOKENS.includes(refreshToken)) {
    return res.status(403).send('Invalid Refresh Token');
  }
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Refresh Token');
    }
    console.log(user);
    const accessToken = jwt.sign({ email: user.email }, SECRET, { expiresIn: '5s' });
    const body = {};
    body.accessToken = accessToken;
    res.status(200).send(body);
    next();
  });
};

exports.logout = (req, res, next) => {
  if (req.body.token === nul) {
    return res.status(400).send('Refresh Token Required');
  }
  if (!REFRESHTOKENS.includes(req.body.token)) {
    return res.status(400).send('Invalid Refresh Token');
  }
  REFRESHTOKENS = REFRESHTOKENS.filter((token) => {
    token !== req.body.token;
  });
  res.status(200).send('User Logged Out Successfully');
};

exports.users = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token === null) {
    return res.status(401).send('Access Token Required');
  }
  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Access Token');
    }

    const body = {};
    for (let user1 of USERS) {
      if (user1.email === user.email) {
        if (user1.isAdmin) {
          body.users = USERS;
          return res.status(200).send(body);
        }
      }
    }
    next();
  });
};
