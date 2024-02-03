class InvalidLogin extends Error {
    constructor(message) {
        super(message)
    }
}

module.exports = InvalidLogin