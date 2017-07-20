const { db, config } = require('../pgp.js');
const User = require('../models/user');

const user = new User(db);
// use Bcrypt for hasing passwords
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const passportJWT = require('passport-jwt');
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

//
module.exports = function (app, passport) {
    // HOME PAGE
    app.get('/', (req, res) => {
        // res.sendFile('login.html', { root: '/home/linh/Desktop/User example/views' });
        console.log(req.user);
        res.render('index', { message: req.flash('localMessage') });
    });

    // ============================
    // LOCAL LOG IN & SIGN UP
    // ============================
    app.get('/local', (req, res) => {
        res.render('login', { message: req.flash('localMessage') });
    });

    // handle sign up request
    app.post('/sign-up', passport.authenticate('local-signup', {
        successRedirect: '/profile', // redirect to the secure profile section
        failureRedirect: '/local', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    }));

    // handle log in request
    app.post('/log-in', passport.authenticate('local-login', {
        successRedirect: '/profile', // redirect to the secure profile section
        failureRedirect: '/local', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    }));

    app.get('/jwt', (req, res) => {
        res.render('login-jwt', { message: req.flash('localMessage') })
    });

    // app.post('/jwt-login', passport.authenticate('jwt-login', {
    //     successRedirect: '/profile',
    //     failureRedirect: '/jwt',
    //     failureFlash: true
    // }));
    // config options for JWT
    const jwtOptions = {};
    jwtOptions.jwtFromRequest = ExtractJwt.fromAuthHeader();
    jwtOptions.secretOrKey = '08052017checkingkey';
    
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
    // secure jwt request
    app.get('/secret', passport.authenticate('jwt', { session: false }), (req, res) => {
        console.log('SECRET GET');
        console.log(JSON.stringify(req.headers));
        console.log(req.session);
        //console.log(req.user);
        res.json({ secretMsg: "This is a secret message" });
    });
    // ============================
    // LOGOUT
    // ============================
    app.get('/logout', (req, res) => {
        req.logout();
        res.redirect('/');
    });

    // =============================
    // PROFILE SECTION
    // =============================
    // we will want this protected so you have to be logged in to visit
    // we will use route middleware to verify this (the isLoggedIn function)

    // route middleware to make sure a user is logged in
    const isLoggedIn = (req, res, next) => {
        // if user is authenticated in the session, carry on 
        if (req.isAuthenticated())
            return next();
        // if they aren't redirect them to the home page
        res.redirect('/');
    }
    app.get('/profile', isLoggedIn, (req, res) => {
        console.log(req.session);
        res.render('profile', {
            user: req.user // get the user out of session and pass to template
        });
    });

    // ===========================
    // GITHUB
    // ===========================
    app.get('/github', passport.authenticate('github'));

    app.get('/github/callback',
        passport.authenticate('github', {
            successRedirect: '/profile',
            failureRedirect: '/',
            failureFlash: true // allow flash messages
        }),
        function (req, res) {
            // Successful authentication
            res.json(req.user);
        });

    // ===========================
    // FACEBOOK
    // ===========================
    app.get('/facebook', passport.authenticate('facebook', { scope: 'email' }));

    app.get('/facebook/callback',
        passport.authenticate('facebook', {
            successRedirect: '/profile',
            failureRedirect: '/',
            failureFlash: true // allow flash messages
        }),
        function (req, res) {
            // Successful authentication
            res.json(req.user);
        });

    // ===========================
    // GOOGLE
    // ===========================
    app.get('/google', passport.authenticate('google', { scope: 'email' }));

    app.get('/google/callback',
        passport.authenticate('google', {
            successRedirect: '/profile',
            failureRedirect: '/',
            failureFlash: true // allow flash messages
        }),
        function (req, res) {
            // Successful authentication
            res.json(req.user);
        });

    // =============================================================================
    // AUTHORIZE (ALREADY LOGGED IN / CONNECTING OTHER SOCIAL ACCOUNT) =============
    // =============================================================================

    // locally --------------------------------
    app.get('/connect/local', function (req, res) {
        res.render('connect-local', { message: req.flash('localMessage') });
    });
    app.post('/connect/local', passport.authenticate('local-signup', {
        successRedirect: '/profile', // redirect to the secure profile section
        failureRedirect: '/connect/local', // redirect back to the signup page if there is an error
        failureFlash: true // allow flash messages
    }));

    // github --------------------------------
    // send to github to do the authentication
    app.get('/connect/github', passport.authorize('github'));

    // handle the callback after github has authorized the user
    app.get('/connect/github/callback',
        passport.authorize('github', {
            successRedirect: '/profile',
            failureRedirect: '/',
            failureFlash: true // allow flash messages
        }));

    // google --------------------------------
    // send to google to do the authentication
    app.get('/connect/google', passport.authorize('google', { scope: 'email' }));

    // handle the callback after google has authorized the user
    app.get('/connect/google/callback',
        passport.authorize('google', {
            successRedirect: '/profile',
            failureRedirect: '/',
            failureFlash: true // allow flash messages
        }));

    // =============================================================================
    // UNLINK ACCOUNTS =============================================================
    // =============================================================================

    // local -----------------------------------
    app.get('/unlink/local', isLoggedIn, function (req, res) {
        user.updateLocal(undefined, undefined, req.user.user_id)
            .then(data => {
                console.log('Unlink local success');
                res.redirect('/profile');
            })
            .catch(err => {
                console.log(err);
            });
    });

    // github -------------------------------
    app.get('/unlink/github', isLoggedIn, function (req, res) {
        user.updateGithub(undefined, undefined, undefined, req.user.user_id)
            .then(data => {
                console.log('Unlink github success');
                res.redirect('/profile');
            })
            .catch(err => {
                console.log(err);
            });
    });

    // google -------------------------------
    app.get('/unlink/google', isLoggedIn, function (req, res) {
        user.updateGoogle(undefined, undefined, undefined, req.user.user_id)
            .then(data => {
                console.log('Unlink google success');
                res.redirect('/profile');
            })
            .catch(err => {
                console.log(err);
            });
    });

    // ==========================================
    // Handle 404 error. 
    // The last middleware.
    app.use("*", function (req, res) {
        res.status(404).send('404');
    });
}