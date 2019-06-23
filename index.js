const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

//import bcrypt
const bcrypt = require('bcryptjs');

//import restricted middleware
const restricted = require('./auth/restricted-middleware.js');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
    res.send('Succesful server setup!');
});


server.post('/api/register', (req, res) => {
    let user = req.body;
  
    // if no username or password return error
    if (!user.username || !user.password) {
      return res.status(500).json({ message: "Need username and passoword!"});
    }
  
    // if password is less than 8 characters return error
    if (user.password.length < 8) {
      return res.status(400).json({ message: "Password to short!"});
    }
  
    const hash = bcrypt.hashSync(user.password, 12);
  
    user.password = hash;
  
    Users.add(user)
      .then(saved => {
        res.status(201).json(saved);
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
  
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          res.status(200).json({ message: `Welcome ${user.username}!` });
        } else {
          res.status(401).json({ message: 'You shall not pass!' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  server.get('/api/users', restricted, (req, res) => {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  });


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on http://localhost:${port} **\n`));
