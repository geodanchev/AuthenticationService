const express = require('express')
const app = express()
const port = 3000
var bodyParser = require('body-parser')
const NodeRSA = require('node-rsa');

const key = new NodeRSA({ b: 512 });

app.use(express.static('public'));

app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
}));

app.post('/login', (req, res) => {
    var name = req.body.userName,
        pass = req.body.password,
        user = authenticate(name, pass);

    if (!user) {
        return res.send('no such user / password');
    }

    var authorization = authorize(user);

    var licensing = getLicense(user);

    if (!licensing) {
        return res.send('no license available');
    }

    var header = Buffer.from(JSON.stringify(createJWTHeader())).toString("base64"),
        body = Buffer.from(JSON.stringify(createJWTBody(user, authorization, licensing))).toString("base64"),
        signature = Buffer.from(JSON.stringify(createSignature(header, body))).toString("base64");

    res.send([header, body, signature].join("."));
});

authenticate = (username, pass) => {
    return {
        Username: username,
        Name: "John Doe",
        Id: "1"
    }
}

authorize = (user) => {
    return {
        roles: ["admin"]
    }
}

getLicense = (user) => {
    return {
        license: "pro"
    }
}
createSignature = (header, body) => {
    return key.encrypt(header + body, "base64");
}

createJWTBody = (user, authorization, licensing) => {
    return {
        iss: "GAMS",
        exp: Date.now() + 1000 * 60 * 5,
        aud: "for everybody",
        sub: user.Id,
        name: user.Name,
        roles: authorization.roles,
        license: licensing.license
    }
}

createJWTHeader = () => {
    return {
        typ: "JWT",
        alg: "RS256"
    }
}


app.listen(port, () => console.log(`Example app listening on port ${port}!`))