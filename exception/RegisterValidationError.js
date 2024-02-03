class RegisterValidationError extends Error {
    constructor(message) {
        super(message)
    }
}

module.exports = RegisterValidationError