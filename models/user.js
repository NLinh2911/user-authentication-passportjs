'use strict';
const bcrypt = require('bcryptjs');

class User {
    constructor(db) {
        this.db = db;
    }

    selectUser(email) {
        return this.db.oneOrNone("SELECT * FROM user_account_passport WHERE email= $1", [email]);
    }
    selectUserGithub(username) {
        return this.db.oneOrNone("SELECT * FROM user_account_passport WHERE github_username= $1", [username]);
    }
    selectUserFb(id) {
        return this.db.oneOrNone("SELECT * FROM user_account_passport WHERE fb_id= $1", [id]);
    }
    selectUserGoogle(id) {
        return this.db.oneOrNone("SELECT * FROM user_account_passport WHERE google_id= $1", [id]);
    }
    selectUserById(user_id) {
        return this.db.oneOrNone("SELECT * FROM user_account_passport WHERE user_id = $1", [user_id]);
    }
    addUser(email, hash) {
        return this.db.one("INSERT INTO user_account_passport(email, pass) VALUES($1, $2) RETURNING *", [email, hash]);
    }
    addUserGithub(github_id, github_username, github_token) {
        return this.db.one("INSERT INTO user_account_passport(github_id, github_username, github_token) VALUES($1, $2, $3) RETURNING *", [github_id, github_username, github_token]);
    }
    addUserFb(fb_id, fb_name, fb_email, fb_token) {
        return this.db.one("INSERT INTO user_account_passport(fb_id, fb_name, fb_email, fb_token) VALUES($1, $2, $3, $4) RETURNING *", [fb_id, fb_name, fb_email, fb_token]);
    }
    addUserGoogle(google_id, google_email, google_token) {
        return this.db.one("INSERT INTO user_account_passport(google_id, google_email, google_token) VALUES($1, $2, $3) RETURNING *", [google_id, google_email, google_token]);
    }
    updateLocal (email, pass, user_id) {
        return this.db.one("UPDATE user_account_passport SET email = $1, pass = $2 WHERE user_id = $3 RETURNING *", [email, pass, user_id]);
    }
    updateGithub (id, username, token, user_id) {
        return this.db.one("UPDATE user_account_passport SET github_id = $1, github_username = $2, github_token = $3 WHERE user_id = $4 RETURNING *", [id, username, token, user_id]);
    }
    updateFb (id, name, email, token, user_id) {
        return this.db.one("UPDATE user_account_passport SET fb_id = $1, fb_name = $2, fb_email = $3, fb_token = $4 WHERE user_id = $5 RETURNING *", [id, name, email, token, user_id]);
    }
    updateGoogle (id, email, token, user_id) {
        return this.db.one("UPDATE user_account_passport SET google_id = $1, google_email = $2, google_token = $3 WHERE user_id = $4 RETURNING *", [id, email, token, user_id]);
    }
    generateHash(password) {
        return bcrypt.hashSync(password, bcrypt.genSaltSync(5), null);
    }
    validPassword(password, pass) {
        return bcrypt.compareSync(password, pass);
    }
}

module.exports = User;