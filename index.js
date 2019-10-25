const express = require('express');
const port = 4000;
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const exjwt = require('express-jwt');
const db = require('./db');
const bcrypt = require('bcryptjs');
const saltRounds = 4;
// Instantiating the express app
const app = express();


// See the react auth blog in which cors is required for access
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization');
    next();
});

// Setting up bodyParser to use json and set it to req.body
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// INstantiating the express-jwt middleware
const jwtMW = exjwt({
    secret: 'madebyken'
});



// LOGIN ROUTE
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.query('SELECT username, password, idUser FROM users WHERE username = ?', [username]).then(dbResults => {

        if(dbResults.length == 0)
        {
          return res.status(401).json({
            sucess: false,
            token: null,
            err: 'Username or password is incorrect'
        });
        }
        bcrypt.compare(password, dbResults[0].password).then(bcryptResult => {
          if(bcryptResult == true)
          {
            let token = jwt.sign({ id: dbResults[0].idUser, username: dbResults[0].username }, 'madebyken', { expiresIn: 129600 }); // Sigining the token
            res.json({
                sucess: true,
                err: null,
                token
            });
          }
          else
          {
            return res(null, false);
          }
        })
    
      }).catch(dbError => cb(err))
    });
    

app.post('/register', (req, res) => {
    let username = req.body.username.trim();
    let password = req.body.password.trim();
    
    if((typeof username === "string") &&
       (username.length > 4) &&
       (typeof password === "string") &&
       (password.length > 4))
    {
      bcrypt.hash(password, saltRounds).then(hash =>
        db.query('INSERT INTO users (username, password) VALUES (?,?)', [username, hash])
      )
      .then(dbResults => {
          console.log(dbResults);
          res.sendStatus(201);
      })
      .catch(error => res.sendStatus(500));
    }
    else {
      console.log("incorrect username or password, both must be strings and username more than 4 long and password more than 6 characters long");
      res.sendStatus(400);
    }
  })

app.get('/', jwtMW /* Using the express jwt MW here */, (req, res) => {
    res.send('You are authenticated'); //Sending some response when authenticated
});

app.get('/chargers', (req,res) => {
    db.query('SELECT * FROM chargerinfo').then(results => {
      res.json(results);
    })
  })
  
  app.get('/chargers/:id', (req,res) => {
    db.query('SELECT * FROM chargerinfo WHERE idCharger = ?',[req.params.id]).then(results => {
      res.json(results);
    })
  })

// Error handling 
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') { // Send the error rather than to show it on the console
        res.status(401).send(err);
    }
    else {
        next(err);
    }
});

/* DB init */
Promise.all(
    [
        db.query(`CREATE TABLE IF NOT EXISTS users(
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(32),
            password VARCHAR(256)
        )`)
        // Add more table create statements if you need more tables
    ]
  ).then(() => {
    console.log('database initialized');
    app.listen(port, () => {
        console.log(`Example API listening on http://localhost:${port}\n`);
    });
  })
  .catch(error => console.log(error));


