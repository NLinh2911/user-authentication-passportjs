# User Authentication with Passportjs and Postgres

## Tutorials:
* Adaptation from Scotch.io: Easy Node Authentication Tutorial

1. Passport-local 
2. Passport-github2

* Passport serialize
* Passport deserialize
* Passport authenticate
* If an user is logged in, passport assigns req.user = object that we pass to serialize via callback function *done(null, user)*

## User_account table in Postgres

```sql
    CREATE TABLE user_account_passport(user_id serial PRIMARY KEY, email TEXT UNIQUE, pass TEXT, github_id TEXT UNIQUE, github_username TEXT UNIQUE, github_token TEXT, google_id TEXT UNIQUE, google_email TEXT UNIQUE, google_token TEXT,  fb_id TEXT UNIQUE, fb_name TEXT, fb_email TEXT, fb_token TEXT);
```

* Local accounts require at least username/email and password
* If we want to link local accounts to other social accounts, the table must have sufficient columns
* User_id: serial PRIMARY KEY
* Email: local account TEXT UNIQUE 
* Pass: local account TEXT
* Github_username: github account TEXT
* Github_id: githuc account TEXT
* Github_token: github account TEXT
* Fb_id
* Fb_name
* Fb_email
* Fb_token
* Google_id
* Google_email
* Google_token

## User can register local account or log in via Github or Google
1. After registering successfully, the user can see profile page with account information
2. After signing up a local account, the user can link or unlink social accounts
3. The local email or social media accounts are only linked to one user. No two local emails share the same social accounts or vice versa. 

## JWT: assign a token to user when they are logged in 
The token is created with a secret or key which can be a vunerability if the key is stolen or lost. 
* For secure request the token is added to request header
```
Authorization: 'JWT JWT_Token_string'
```
* Each time you access the secure request, passport.authenticate('jwt',...) is called to validate the token
* When testing passport-jwt in *server-jwt.js*, JWT is mainly used for REST API which is stateless. In default, there is no data passed between requests.
* Compared to other strategies e.g. *passport-local*, passport utilizes *passport.serializeUser()* to bind user data to req.user (which is taken from req.session.passport.user). *passport.deserializeUser()* is called on each request and gets the user.id stored in req.user by serializeUser() to query the databse to check if the user exists.