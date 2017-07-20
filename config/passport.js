// load all the things we need
const { db, config } = require('../pgp');
const bcrypt = require('bcryptjs');

const LocalStrategy = require('passport-local').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GithubStrategy = require('passport-github2').Strategy;
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
//
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');

const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;
//
const User = require('../models/user');
const user = new User(db);

// load the auth variables
const configAuth = require('./auth'); // use this one for testing

module.exports = function (passport) {
    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
    // required for persistent login sessions
    // passport needs ability to serialize and unserialize users out of session

    // used to serialize the user for the session
    passport.serializeUser(function (user, done) {
        console.log('user serialize');
        done(null, user.user_id);
    });

    // used to deserialize the user
    passport.deserializeUser(function (user_id, done) {
        console.log('user deserialize');
        user.selectUserById(user_id)
            .then(user => {
                done(null, user);
            })
            .catch(err => {
                done(err);
            })
    });

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    // we are using named strategies since we have one for login and one for signup
    // by default, if there was no name, it would just be called 'local'

    passport.use('local-signup', new LocalStrategy({
        // by default, local strategy uses username and password, we will override with email
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true // allows us to pass back the entire request to the callback
    },
        function (req, email, password, done) {

            // asynchronous
            // wont fire unless data is sent back
            process.nextTick(function () {
                console.log(req.user);
                console.log(!req.user);
                // if the user is not already logged in
                if (!req.user) {
                    // find a user whose email is the same as the forms email
                    user.selectUser(email)
                        .then(data => {
                            if (data !== null) {
                                // this email already exists
                                return done(null, false, req.flash('localMessage', 'That email is already taken.'));
                            } else {
                                // this email does not yet exist
                                // hasing password by auto-generating a salt and hash
                                let hashPass = user.generateHash(password);
                                user.addUser(email, hashPass)
                                    .then(newUser => {
                                        console.log('Sign up success');
                                        return done(null, newUser);
                                    });
                            }
                        })
                        .catch(err => {
                            console.log(err);
                        })
                    // if the user is logged in but has no local account...
                } else if (!req.user.email) {
                    // ...presumably they're trying to connect a local account
                    // BUT let's check if the email used to connect a local account is being used by another user
                    user.selectUser(email)
                        .then(data => {
                            if (data !== null) {
                                // this local email already exists
                                return done(null, false, req.flash('localMessage', 'That email is already taken.'));
                            } else {
                                let hashPass = user.generateHash(password);
                                user.updateLocal(email, hashPass, req.user.user_id)
                                    .then(newUser => {
                                        console.log('Link local account success');
                                        return done(null, newUser);
                                    });
                            }
                        })
                        .catch(err => {
                            console.log(err);
                        })
                } else {
                    // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                    return done(null, req.user);
                }
            });
        }));

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================

    passport.use('local-login', new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
        function (req, email, password, done) {
            if (email)
                email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

            // asynchronous
            process.nextTick(function () {
                // if the user is not already logged in
                console.log(req.user);
                if (!req.user) {
                    user.selectUser(email)
                        .then(data => {
                            if (data === null) {
                                // no account exits
                                return done(null, false, req.flash('localMessage', 'No user found.'));
                            } else {
                                // check password
                                if (!user.validPassword(password, data.pass)) {
                                    return done(null, false, req.flash('localMessage', 'Oops! Wrong password.'));
                                } else {
                                    console.log('Log in success');
                                    return done(null, data);
                                }
                            }
                        })
                        .catch(err => {
                            console.log(err);
                        });
                } else {
                    // user is logged in and already has a local account. Ignore signup. (You should log out before trying to create a new account, user!)
                    return done(null, req.user);
                }
            });
        }));

    // =========================================================================
    // JWT LOGIN ===============================================================
    // =========================================================================
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
    passport.use(strategy);


    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use('facebook', new FacebookStrategy({

        // pull in our app id and secret from our auth.js file
        clientID: configAuth.facebookAuth.clientID,
        clientSecret: configAuth.facebookAuth.clientSecret,
        callbackURL: configAuth.facebookAuth.callbackURL,
        profileFields: ['email'],
        passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
    },
        // facebook will send back the token and profile
        function (token, refreshToken, profile, done) {
            // asynchronous
            process.nextTick(function () {
                console.log(profile);
                let fbId = (profile.id).toString();
                let fbname = profile.name.givenName + ' ' + profile.name.familyName;
                let fbemail = (profile.emails[0].value || '').toLowerCase();
                // find the user in the database based on their facebook id
                user.selectUserfb(fbId)
                    .then(data => {
                        // add account if not already exists
                        if (data === null) {
                            // use github id as pass
                            //let hashPass = user.generateHash((profile.id).toString());
                            user.addUserFb(fbId, fbname, fbemail, token)
                                .then(newUser => {
                                    console.log('Sign up with Facebook success');
                                    return done(null, newUser);
                                });
                        } else {
                            // github acc already exists
                            return done(null, data);
                        }
                    })
                    .catch(err => {
                        console.log(err);
                        done(null, false, req.flash('localMessage', 'Log in facebook error'));
                    })
            })
        }
    ));


    // =========================================================================
    // GITHUB ================================================================
    // =========================================================================
    passport.use(new GithubStrategy({
        clientID: configAuth.githubAuth.clientID,
        clientSecret: configAuth.githubAuth.clientSecret,
        callbackURL: configAuth.githubAuth.callbackURL,
        passReqToCallback: true // allows us to pass back the entire request to the callback
    },
        function (req, accessToken, refreshToken, profile, done) {
            let githubId = (profile.id).toString();

            process.nextTick(function () {
                // if the user is not already logged in
                console.log(req.user);
                console.log(!req.user);
                if (!req.user) {
                    user.selectUserGithub(profile.username)
                        .then(data => {
                            // add account if not already exists
                            if (data === null) {
                                //console.log(profile);
                                //console.log(accessToken);
                                //let hashId = user.generateHash((profile.id).toString());
                                user.addUserGithub(githubId, profile.username, accessToken)
                                    .then(newUser => {
                                        console.log('Sign up with Github success');
                                        return done(null, newUser);
                                    });
                            } else {
                                // github acc already exists
                                console.log('Github acc exists!!!');
                                return done(null, data);
                            }
                        })
                        .catch(err => {
                            console.log(err);
                            done(null, false, req.flash('localMessage', 'Log in github error'));
                        })
                } else {
                    // user is logged in -> link github account
                    // check if the acc is already linked
                    user.selectUserGithub(profile.username)
                        .then(data => {
                            if (data !== null) {
                                // this github username already exists
                                return done(null, false, req.flash('localMessage', 'That Github acc is already linked.'));
                            } else {
                                user.updateGithub(githubId, profile.username, accessToken, req.user.user_id)
                                    .then(data => {
                                        console.log('Link github acc success');
                                        return done(null, data);
                                    })
                                    .catch(err => {
                                        console.log(err);
                                        done(null, false, req.flash('localMessage', 'Link github acc error'))
                                    })
                            }
                        })
                }
            })
        }
    ));


    // =========================================================================
    // GOOGLE ==================================================================
    // =========================================================================
    passport.use(new GoogleStrategy({

        clientID: configAuth.googleAuth.clientID,
        clientSecret: configAuth.googleAuth.clientSecret,
        callbackURL: configAuth.googleAuth.callbackURL,
        passReqToCallback: true // allows us to pass in the req from our route (lets us check if a user is logged in or not)

    },
        function (req, token, refreshToken, profile, done) {

            // asynchronous
            process.nextTick(function () {
                //console.log(token);
                console.log(req.user);
                console.log(!req.user);
                let ggemail = (profile.emails[0].value || '').toLowerCase();
                // check if the user is already logged in
                if (!req.user) {
                    user.selectUserGoogle(profile.id)
                        .then(data => {
                            // add account if not already exists
                            if (data === null) {
                                user.addUserGoogle(profile.id, ggemail, token)
                                    .then(newUser => {
                                        console.log('Sign up with Google success');
                                        return done(null, newUser);
                                    });
                            } else {
                                // google acc already exists
                                console.log('Google acc exists!!!');
                                return done(null, data);
                            }
                        })
                        .catch(err => {
                            console.log(err);
                            done(null, false, req.flash('localMessage', 'Log in google error'));
                        })
                } else {
                    // user is logged in -> link google account
                    // check if the acc is already linked
                    user.selectUserGoogle(profile.id)
                        .then(data => {
                            if (data !== null) {
                                // this google username already exists
                                return done(null, false, req.flash('localMessage', 'That Google acc is already linked.'));
                            } else {
                                user.updateGoogle(profile.id, ggemail, token, req.user.user_id)
                                    .then(data => {
                                        console.log('Link google acc success');
                                        return done(null, data);
                                    })
                                    .catch(err => {
                                        console.log(err);
                                        done(null, false, req.flash('localMessage', 'Link google acc error'))
                                    })
                            }
                        })
                }
            })
        }
    ));
};

