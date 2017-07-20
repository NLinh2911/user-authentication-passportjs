// config/auth.js

// expose our config directly to our application using module.exports
module.exports = {

    'facebookAuth' : {
        'clientID'        : '107481626493248', // your App ID
        'clientSecret'    : 'f6a6b0c04c8b61c5271f147408742d20', // your App Secret
        'callbackURL'     : 'http://localhost:8080/facebook/callback',
        //'profileURL': 'https://graph.facebook.com/v2.5/me?fields=first_name,last_name,email'

    },

    'githubAuth' : {
        'clientID'        : '7d045905caad0446a6d1', // your App ID
        'clientSecret'    : '3e4b4aa1bef91f1513d76171afd75156a17bc2e6', // your App Secret
        'callbackURL'     : 'http://127.0.0.1:8080/github/callback',
    },

    'googleAuth' : {
        'clientID'        : '904683444733-qi7e8co1ceofeqbcs323s6h7a1tjs02u.apps.googleusercontent.com', // your App ID
        'clientSecret'    : '2HxRymXwgS9Cs3IowelxDI3Z', // your App Secret
        'callbackURL'     : 'http://localhost:8080/google/callback',
    }
};
