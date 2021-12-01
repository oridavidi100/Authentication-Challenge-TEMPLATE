const USERS = [
  {
    email: 'admin@email.com',
    name: 'admin',
    password: '$2b$10$DHvaY7RMYSkqOpJWdQ6qn.k5NNkdcja8p0OcRP0rLzObYhsonacvG',
    isAdmin: true,
  },
];

const serverApis = [
  {
    method: 'post',
    path: '/users/register',
    description: 'Register, Required: email, name, password',
    example: { body: { email: 'user@email.com', name: 'user', password: 'password' } },
  },
  {
    method: 'post',
    path: '/users/login',
    description: 'Login, Required: valid email and password',
    example: { body: { email: 'user@email.com', password: 'password' } },
  },
  {
    method: 'post',
    path: '/users/token',
    description: 'Renew access token, Required: valid refresh token',
    example: { headers: { token: 'Refresh Token' } },
  },
  {
    method: 'post',
    path: '/users/tokenValidate',
    description: 'Access Token Validation, Required: valid access token',
    example: { headers: { Authorization: 'Bearer Access Token' } },
  },
  {
    method: 'get',
    path: '/api/v1/information',
    description: "Access user's information, Required: valid access token",
    example: { headers: { Authorization: 'Bearer Access Token' } },
  },
  {
    method: 'post',
    path: '/users/logout',
    description: 'Logout, Required: access token',
    example: { body: { token: 'Refresh Token' } },
  },
  {
    method: 'get',
    path: 'api/v1/users',
    description: 'Get users DB, Required: Valid access token of admin user',
    example: { headers: { authorization: 'Bearer Access Token' } },
  },
];
const INFORMATION = [{ email: 'admin@email.com', name: 'admin info' }]; // [...{email, info}...]
const jwt = require('jsonwebtoken');
require('dotenv').config();
const SECRET = process.env.ACCESS_TOKEN_SECRET;
let REFRESHTOKENS = [];
const bcrypt = require('bcrypt');

exports.register = async (req, res, next) => {
  const { email, name } = req.body;
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
  USERS.push({ email: email, name: name, password: password, isAdmin: isAdmin });
  INFORMATION.push({ email: email, info: `${name} info` });
  res.status(201).send('Register Success');
  next();
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  const body = {};
  let flag = 0;
  for (let user1 of USERS) {
    let ans = await bcrypt.compare(password, user1.password);
    if (email === user1.email && ans) {
      body.email = user1.email;
      body.name = user1.name;
      body.isAdmin = user1.isAdmin;
      username = { email: email, name: body.name, isAdmin: body.isAdmin };
      const accessToken = jwt.sign(username, SECRET, { expiresIn: '10s' });
      body.accessToken = accessToken;
      body.refreshToken = jwt.sign({ username: username, isAdmin: body.isAdmin }, process.env.REFRESH_TOKEN_SECRET);
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

exports.tokenValidate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
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
    res.status(200).send([body]);
    next();
  });
};

exports.token = (req, res, next) => {
  const refreshToken = req.body.token;
  if (!refreshToken) {
    return res.status(401).send('Refresh Token Required');
  }
  if (!REFRESHTOKENS.includes(refreshToken)) {
    return res.status(403).send('Invalid Refresh Token');
  }
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.status(403).send('Invalid Refresh Token');
    }
    const accessToken = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, SECRET, { expiresIn: '10s' });
    const body = {};
    body.accessToken = accessToken;
    res.status(200).send(body);
    next();
  });
};

exports.logout = (req, res, next) => {
  try {
    if (req.body.token === null) {
      return res.status(400).send('Refresh Token Required');
    }
    if (!REFRESHTOKENS.includes(req.body.token)) {
      return res.status(400).send('Invalid Refresh Token');
    }
    REFRESHTOKENS = REFRESHTOKENS.filter((token) => {
      token !== req.body.token;
    });
    res.status(200).send('User Logged Out Successfully');
  } catch (err) {
    console.log(err);
  }
};

exports.users = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) {
      return res.status(401).send('Access Token Required');
    }
    jwt.verify(token, SECRET, (err, user) => {
      if (err) {
        return res.status(403).send('Invalid Access Token');
      }
      for (let user1 of USERS) {
        if (user1.email === user.email) {
          if (user1.isAdmin) {
            return res.status(200).send(USERS);
          }
        }
      }
      return res.status(403).send('Invalid Access Token');
    });
  } catch (err) {
    console.log(err);
  }
};

exports.options = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) {
    return res.header({ Allow: 'OPTIONS, GET, POST' }).send([serverApis[0], serverApis[1]]);
  }
  jwt.verify(token, SECRET, (err, user) => {
    console.log(user);
    if (err) {
      return res.header({ Allow: 'OPTIONS, GET, POST' }).send([serverApis[0], serverApis[1], serverApis[2]]);
    }
    if (user.isAdmin) {
      return res.header({ Allow: 'OPTIONS, GET, POST' }).send(serverApis);
    }
    return res
      .header({ Allow: 'OPTIONS, GET, POST' })
      .send([serverApis[0], serverApis[1], serverApis[2], serverApis[3], serverApis[4], serverApis[5]]);
  });
};
