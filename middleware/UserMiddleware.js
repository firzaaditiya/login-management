const jwt = require("jsonwebtoken")
require("dotenv").config()

const tokenVerify = (req, res, next) => {
    const cookie = req.cookies[Buffer.from("Authorization_Token", "utf-8").toString("base64").slice(0, Buffer.from("Authorization_Token", "utf-8").toString("base64").length - 2)]

    if (!cookie) {
        return res.status(401).redirect("/users/login")
    }

    const token = cookie && cookie.split(" ")[1]

    jwt.verify(token, process.env.JWT_KEY, (error, decoded) => {
        if (error) {
            return res.status(401).redirect("/users/login")
        }

        req.user = decoded
        return next()
    })
}

const mustNotLogin = (req, res, next) => {
    const cookie = req.cookies[Buffer.from("Authorization_Token", "utf-8").toString("base64").slice(0, Buffer.from("Authorization_Token", "utf-8").toString("base64").length - 2)]

    if (!cookie) {
        return next()
    } else {
        const token = cookie && cookie.split(" ")[1]
        jwt.verify(token, process.env.JWT_KEY, (error, decoded) => {
            if (error) {
                return next()
            } else {
                req.user = decoded
                return res.redirect("/dashboard")
            }
        })
    }
}

module.exports = {
    tokenVerify,
    mustNotLogin
}