const Express = require("express");
const BodyParser = require("body-parser");
const Speakeasy = require("speakeasy");

var app = Express();

app.use(BodyParser.json());
app.use(BodyParser.urlencoded({ extended: true }));


/* ## Generates Secret Code for Authenticator App
 * This secret is generated when the user activates the 2FA.
 * After its generation, it never leaves the backend and is
 * stored in the database, associated to that particular user.
*/
app.post("/secret", (request, response, next) => {
    var secret = Speakeasy.generateSecret({ length: 20 });
    response.send({ "secret": secret.base32 });
});

/* ## Generates TOTP
 * This code generates the TOTP based on the UNIX timestamp.
 * Expiration time is generally kept as 30 seconds.
 * It can be extended in the validation process.
*/
app.post("/generate", (request, response, next) => {
    response.send({
        "token": Speakeasy.totp({
            secret: request.body.secret,
            encoding: "base32"
        }),
        "remaining": (30 - Math.floor((new Date()).getTime() / 1000.0 % 30))
    });
});

/* ## Validates TOTP
 * It uses the secret from the database and the code sent by the user.
 * 'window' parameter determines how much lineancy are we allowing in
 * the code-timeout.
*/
app.post("/validate", (request, response, next) => {
    response.send({
        "valid": Speakeasy.totp.verify({
            secret: request.body.secret,
            encoding: "base32",
            token: request.body.token,
            window: 0
        })
    });
});

/* Start Server */
app.listen(3000, () => {
    console.log("Listening at :3000...");
});

