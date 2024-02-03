const jwt = require("jsonwebtoken")
require("dotenv").config()

const createToken = (data) => {
    return jwt.sign(data, process.env.JWT_KEY, {
        expiresIn: "24h"
    })
}

module.exports = {
    createToken
}