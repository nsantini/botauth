"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("crypto");
const cookie = require("cookie");
class CookieResumption {
    constructor(maxAge, secret) {
        this.maxAge = maxAge;
        this.secret = secret;
        this.addresses = {};
    }
    persistHandler() {
        let maxAge = Math.floor(this.maxAge);
        let secret = this.secret;
        return (req, res, next) => {
            let cypher = crypto.createCipher("aes192", secret);
            let cookieValue = cypher.update(req.query.state, "utf8", "base64") + cypher.final("base64");
            this.addresses[req.params.id] = cookie.serialize("botauth", cookieValue, { maxAge: maxAge, httpOnly: true });
            next();
        };
    }
    restoreHandler() {
        let secret = this.secret;
        return (req, res, next) => {
            let cookies = cookie.parse(this.addresses[req.params.id]);
            if (cookies && cookies.botauth) {
                let decypher = crypto.createDecipher("aes192", secret);
                let cookieValue = decypher.update(cookies.botauth, "base64", "utf8") + decypher.final("utf8");
                req.locals = req.locals || {};
                req.locals.resumption = cookieValue;
                res.header("Set-Cookie", cookie.serialize("botauth", "", { maxAge: 0, httpOnly: true }));
            }
            next();
        };
    }
    ;
}
exports.CookieResumption = CookieResumption;
