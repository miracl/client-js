// In memory storage for users
var storage = require("./storage.js");

// Load the crypto library
global.CTX = require("@miracl/crypto-js");

// Reusable test data
global.testData = {
    init: function () {
        return {
            authurl: "http://server.com/authorize",
            server: "http://server.com",
            customerId: "customerId",
            seed: "hexSeed",
            defaultPinLength: 4,
            userStorage: new storage()
        };
    },
    settings: function () {
        return {
            dtaUrl: "https://api.miracl.net",
            registerURL: "https://api.miracl.net/register/user",
            signatureURL: "https://api.miracl.net/signature",
            mpinAuthServerURL: "https://api.miracl.net/rps",
            dvsRegURL: "https://api.miracl.net/dvs/register"
        };
    }
};
