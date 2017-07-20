// server.js - use passportjs with postgres

// set up  ======================================================================
// get all the tools we need
const express = require('express');
const app = express();
const port = process.env.PORT || 8080;
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const flash = require('connect-flash');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const nunjucks = require('nunjucks');

const bcrypt = require('bcryptjs');

const { db, config } = require('./pgp');
const User = require('./models/user');
const user = new User(db);

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

// set up our express application
app.use(morgan('dev')); // log every request to the console
app.use(cookieParser('08052017')); // read cookies (needed for auth)
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
    secret: '08052017', // session secret
    resave: true,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// config options for JWT
const jwtOptions = {};
jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeader();
jwtOptions.secretOrKey = '08052017checkingkey';

const strategy = new JwtStrategy(jwtOptions, (jwt_payload, next) => {
    console.log('payload received', jwt_payload);
    // usually this would be a database call:
    user.selectUserById(jwt_payload.id)
        .then(data => {
            if (data) {
                next(null, data);
            } else {
                next(null, false);
            }
        });
});

// below statements are invoked on every request
passport.use(strategy);
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

// routes ======================================================================
app.get('/', (req, res) => {
    console.log(req.user);
    if (req.session.login === true) {
        console.log('LOGIN TRUE');
        console.log(req.session);
        res.render('index', { login: true });
    } else {
        console.log('LOGIN FALSE');
        console.log(req.session);
        res.render('index', { login: false });
    }
});

app.get('/jwt', (req, res) => {
    res.render('login-jwt')
});

//app.post('/jwt-sign-up')
app.post('/jwt-login', (req, res) => {
    let email;
    let password;
    if (req.body.email && req.body.password) {
        email = req.body.email;
        password = req.body.password;
    }
    // usually this would be a database call:
    user.selectUser(email)
        .then(data => {
            if (!data) {
                res.status(401).json({ message: "no such user found" });
            } else if (!user.validPassword(password, data.pass)) {
                return res.status(401).json({ message: "Oops! Wrong password!!" });
            } else {
                // from now on we'll identify the user by the id and the id is the only personalized value that goes into our token
                const payload = { id: data.user_id, group: "customer" };
                const options = {
                    issuer: 'http://localhost:8080',
                    subject: 'jwt login service',
                    expiresIn: 120 //Expire in 2 minutes
                };
                //Ký vào payload sử dụng secretOrKey
                const token = jwt.sign(payload, jwtOptions.secretOrKey, options, (err, token) => {
                    if (err) {
                        res.status(401).json({ message: "Fail to generate jwt token" });
                    } else {
                        req.session.login = true;
                        req.session.user = data;
                        console.log(req.user);
                        console.log('LOGIN SUCCESS VIA 3001');
                        res.render('profile', { login: true, message: "Token generated ok", token: token, payload: payload, user: data });  //và trả về
                    }
                });
            };
        })
});

app.get('/secret', passport.authenticate('jwt', { session: false }), (req, res) => {
    console.log('SECRET GET');
    console.log(JSON.stringify(req.headers));
    console.log(req.session);
    //console.log(req.user);
    res.json({ secretMsg: "This is a secret message" });
});

// =============================
// PROFILE SECTION
// =============================
// we will want this protected so you have to be logged in to visit
// we will use route middleware to verify this (the isLoggedIn function)

// route middleware to make sure a user is logged in
const isLoggedIn = (req, res, next) => {
    // if user is authenticated in the session, carry on 
    // if (req.isAuthenticated())
    //     return next();
    if (req.session.login) {
        return next();
    }
    // if they aren't redirect them to the home page
    res.redirect('/');
}
app.get('/profile', isLoggedIn, (req, res) => {
    console.log(req.session);
    res.render('profile', {
        user: req.session.user // get the user out of session and pass to template
    });
});

// ============================
// LOGOUT
// ============================
app.get('/logout', (req, res) => {
    req.session.login = false;
    console.log(req.session);
    req.logout();
    res.redirect('/');
});

// launch ======================================================================
app.listen(port);
console.log('The magic happens on port ' + port);
