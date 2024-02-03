const express = require("express")
const app = express()
const methodOverride = require("method-override")
const dotenv = require("dotenv")
const path = require("path")
const cookieParser = require("cookie-parser")

const userController = require("./controller/userController")
const jwtController = require("./controller/jwtController")

const userMiddleware = require("./middleware/UserMiddleware")
const { Error } = require("mongoose")

dotenv.config()
app.use(cookieParser())

// Ini harus berada diatas middleware "method-override"
app.use(express.urlencoded(
    {
        extended: false
    }
))

// Konfigurasi agar middleware "method-override" support via input hidden element, dan tidak menggunakan via Query Params
app.use(methodOverride(function(req, res) {
    if (req.body && typeof req.body === "object" && "_method" in req.body) {
        const method = req.body["_method"]
        delete req.body["_method"]

        return method
    }
}))

app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "/views"))

app.get("/", userMiddleware.mustNotLogin, (req, res) => {
    res.render("home/home")
})

app.get("/users/register", userMiddleware.mustNotLogin, (req, res) => {
    res.render("user/register", {
        message: null
    })
})

app.post("/users/register", userMiddleware.mustNotLogin, async (req, res) => {
    const { username, name, password } = req.body;

    try {
        if (!username || !name || !password) {
            throw new Error("Failed to Register")
        }
        
        await userController.registerUser(username, name, password)
        res.redirect(301, "/")
    } catch (error) {
        res.status(401).render("user/register", {
            message: error.message
        })    
    }
})

app.get("/users/login", userMiddleware.mustNotLogin, (req, res) => {
    res.render("user/login", {
        message: null
    })
})

app.post("/users/login", userMiddleware.mustNotLogin, async (req, res) => {
    const { username, password } = req.body

    try {
        if (!username || !password) {
            throw new Error("Failed to Login")
        }

        const userData = await userController.login(username, password)
        const token = jwtController.createToken(userData)

        const cookieName = Buffer.from("Authorization_Token", "utf-8").toString("base64").slice(0, Buffer.from("Authorization_Token", "utf-8").toString("base64").length - 2)
        res.cookie(cookieName, `Bearer ${token}`, {
            httpOnly: false,
            secure: false,
            expires: new Date(Date.now() + 86400000)
        })
        res.redirect(301, "/dashboard")
    } catch (error) {
        res.render("user/login", {
            message: error.message
        })
    }
})

app.get("/dashboard", userMiddleware.tokenVerify, (req, res) => {
    res.render("home/dashboard")
})

app.get("/users/profile", userMiddleware.tokenVerify, async (req, res) => {
    try {
        const userData = await userController.getUser(req.user.username)

        res.render("user/profile", {
            message: null,
            username: userData.username,
            name: userData.name
        })
    } catch (error) {
        // const cookieName = Buffer.from("Authorization_Token", "utf-8").toString("base64").slice(0, Buffer.from("Authorization_Token", "utf-8").toString("base64").length - 2)
        // res.clearCookie(cookieName)
        res.redirect("/users/profile")
    }
})

app.patch("/users/profile", userMiddleware.tokenVerify, async (req, res) => {
    const { username, name } = req.body

    try {
        const userData = await userController.updateProfileName(username, name)
        res.render("user/profile", {
            message: "Update Profile Success",
            username: userData.username,
            name: userData.name,
            success: true
        })
    } catch(error) {
        res.render("user/profile", {
            message: error.message,
            username: username,
            name: name,
            success: false
        })
    }
})

app.get("/users/password", userMiddleware.tokenVerify, (req, res) => {
    res.render("user/password", {
        message: null,
        username: req.user.username
    })
})

app.patch("/users/password", userMiddleware.tokenVerify, async (req, res) => {
    const { username, oldPassword, newPassword } = req.body

    try {
        const userData = await userController.updatePassword(username, oldPassword, newPassword)

        res.render("user/password", {
            message: "Success Update Password",
            username: userData.username,
            success: true
        })
    } catch(error) {
        res.render("user/password", {
            message: error.message,
            username: username,
            success: false
        })
    }
})

app.get("/users/logout", userMiddleware.tokenVerify, (req, res) => {
    const cookieName = Buffer.from("Authorization_Token", "utf-8").toString("base64").slice(0, Buffer.from("Authorization_Token", "utf-8").toString("base64").length - 2)
    res.clearCookie(cookieName)
    res.redirect("/")
})

app.get("*", (req, res) => {
    res.send("Not Found")
})

app.listen(process.env.PORT, () => {
    console.info("Running on http://localhost:5500")
})