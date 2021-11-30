const USERS = []; // [...{email, name, password, isAdmin}...]
const INFORMATION = []; // [...{email, info}...]
const REFRESHTOKENS = [];

exports.register = (req, res, next) => {
  const { email, user, password } = req.body;
  for (let user of USERS) {
    if (user.email === email) {
      return res.status(409).send('user already exists');
    }
  }
  USERS.push({ email: email, user: user, password: password });
  res.status(201).send('Register Success');
  console.log(USERS);
  next();
};
