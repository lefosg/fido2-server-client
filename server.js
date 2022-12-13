const express       = require('express');
const bodyParser    = require('body-parser');
const expressSession = require('express-session');
const cookieParser  = require('cookie-parser');
const path          = require('path');
const crypto        = require('crypto');
const MongoStore    = require('connect-mongo');

require('./database/db');

//routes
const defaultroutes = require('./routes/default.js');
const webuathnauth  = require('./routes/webauthn.js');

const app           = express();
const port          = 3000;

app.use(bodyParser.json());

/* ----- session ----- */
app.use(expressSession({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: 'mongodb://localhost:27017/expressjs_tutorial' }),
  // Cookie Options
  cookie:{
    maxAge: 24 * 60 * 60 * 1000
  } // 24 hours
}))
app.use(cookieParser())

/* ----- serve static ----- */
app.use(express.static(path.join(__dirname, 'static')));

app.use('/', defaultroutes)
app.use('/webauthn', webuathnauth)

app.listen(port);
console.log("Started app on http://localhost:"+port);
