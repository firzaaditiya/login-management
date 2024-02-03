const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const RegisterValidationError = require("./../exception/RegisterValidationError")
const InvalidLogin = require("./../exception/InvalidLogin")
const UpdateValidationError = require("./../exception/UpdateValidationError")

require("dotenv").config()

mongoose.connect(`mongodb://127.0.0.1:27017/${process.env.DB_NAME}`)

const userSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            minLength: 8,
            maxLength: 30
        },
        name: {
            type: String,
            required: true
        },
        password: {
            type: String,
            required: true,
            minLength: 8
        }
    }
)

const User = mongoose.model("User", userSchema, "users")

const registerUser = async (username, name, password) => {
    try {
        const userData = await User.findOne(
            {
                username: username
            }
        )
    
        if (userData !== null) {
            if (userData.username === username) {
                throw new RegisterValidationError("User is already registered")
            }
        }

        const user = new User(
            {
                username: username,
                name: name,
                password: bcrypt.hashSync(password, bcrypt.genSaltSync(10))
            }
        )

        await user.save()
    } catch (error) {
        if (error instanceof RegisterValidationError) {
            throw new Error(error.message)
        } else {
            throw new Error("Failed to register user")
        }
    }
}

const login = async (username, password) => {
    try {
        const userData = await User.findOne(
            {
                username: username
            }
        )

        if (userData === null) {
            throw new InvalidLogin("Failed to Login, User is not Registered")
        }

        if (userData !== null) {
            if (bcrypt.compareSync(password, userData.password)) {
                return {
                    username: userData.username
                }
            } else {
                throw new InvalidLogin("Failed to Login, Maybe incorrect Username/Password")
            }
        } else {
            throw new InvalidLogin("Failed to Login")
        }
    } catch(error) {
        if (error instanceof InvalidLogin) {
            throw new Error(error.message)
        } else {
            throw new Error("Failed to Login Account")
        }
    }
}

const updateProfileName = async (username, name) => {
    try {
        const oldUser = await User.findOne(
            {
                username: username
            }
        )

        if (oldUser === null) {
            throw new UpdateValidationError("Update failed, invalid user")
        }

        if (name === oldUser.name) {
            throw new UpdateValidationError("Update failed, the name of the profile you want to update is the same as the old name")
        }

        const userData = await User.findOneAndUpdate(
            {
                username: username
            },
            {
                name: name
            },
            {
                new: true,
                runValidators: true
            }
        )

        return {
            username: userData.username,
            name: userData.name
        }
    } catch (error) {
        if (error instanceof UpdateValidationError) {
            throw new Error(error.message)
        } else {
            throw new Error("Update Failed")
        }
    }
}

const getUser = async (username) => {
    try {
        const userData = await User.findOne(
            {
                username: username
            }
        )

        if (userData === null) {
            throw new Error("Error, Invalid User")
        }

        return {
            username: userData.username,
            name: userData.name
        }
    } catch (error) {
        throw new Error(error.message)
    }
}

const updatePassword = async (username, oldPassword, newPassword) => {
    try {
        const userData = await User.findOne(
            {
                username: username
            }
        )
    
        if (userData === null) {
            throw new UpdateValidationError("Update failed, invalid user")
        }
    
        if (bcrypt.compareSync(oldPassword, userData.password)) {
            if (bcrypt.compareSync(newPassword, userData.password)) {
                throw new UpdateValidationError("Update failed, the new password cannot be the same as the old password")
            }

            const user = await User.findOneAndUpdate(
                {
                    username: username
                },
                {
                    password: bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10))
                },
                {
                    runValidators: true
                }
            )
    
            return {
                username: user.username
            }
        } else {
            throw new UpdateValidationError("Update failed, old password is wrong")
        }
    } catch (error) {
        if (error instanceof UpdateValidationError) {
            throw new Error(error.message)
        } else {
            throw new Error("Update Failed")
        }
    }
}

module.exports = {
    registerUser,
    login,
    updateProfileName,
    getUser,
    updatePassword
}