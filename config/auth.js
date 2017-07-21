// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

    'facebookAuth' : {
        'clientID'        : '', // your App ID
        'clientSecret'    : '', // your App Secret
        'callbackURL'     : 'http://localhost:8080/facebook/callback',
        //'profileURL': 'https://graph.facebook.com/v2.5/me?fields=first_name,last_name,email'

    },

    'githubAuth' : {
        'clientID'        : '', // your App ID
        'clientSecret'    : '', // your App Secret
        'callbackURL'     : 'http://127.0.0.1:8080/github/callback',
    },

    'googleAuth' : {
        'clientID'        : '', // your App ID
        'clientSecret'    : '', // your App Secret
        'callbackURL'     : 'http://localhost:8080/google/callback',
    }
};
