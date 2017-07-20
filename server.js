// server.js - use passportjs with postgres

// set up  ======================================================================
// get all the tools we need
const express = require('express');
const app = express();
const port = process.env.PORT || 8080;
const passport = require('passport');
const flash = require('connect-flash');

const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const nunjucks = require('nunjucks');

const { db, config } = require('./pgp');

// check connect to our database 
db.proc('version')
    .then(data => {
        // connection success
        console.log(data);
    })
    .catch(err => {
        console.log(err);
    })
//
require('./config/passport')(passport); // pass passport for configuration

// set up our express application
app.use(morgan('dev')); // log every request to the console
app.use(cookieParser('05052017')); // read cookies (needed for auth)
app.use(bodyParser.json()); // get information from html forms
app.use(bodyParser.urlencoded({ extended: true }));

// set up nunjucks for view template
nunjucks.configure('views', {
    autoescape: false,
    express: app,
    cache: false
});
app.engine('html', nunjucks.render);
app.set('view engine', 'njk');

// required for passport
app.use(session({
    secret: '05052017', // session secret
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false }
}));
// below statements are invoked on every request
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

// routes ======================================================================
require('./routes/routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

// launch ======================================================================
app.listen(port);
console.log('The magic happens on port ' + port);
