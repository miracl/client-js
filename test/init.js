// Mock local storage
var LocalStorage = require('node-localstorage').LocalStorage;
global.localStorage = new LocalStorage('./localStorageTemp');

// Load the crypto library
global.CTX = require("milagro-crypto-js");

// Reusable test data
global.testData = {
    init: function () {
        return {
            server: "http://server.com",
            customerId: "customerId",
            seed: "hexSeed"
        };
    },
    settings: function () {
        return {
            certivoxURL: "https://miracl.com/",
            dtaUrl: "https://api.miracl.net",
            registerURL: "https://api.miracl.net/register/user",
            signatureURL: "https://api.miracl.net/signature",
            mpinAuthServerURL: "https://api.miracl.net/rps",
            dvsRegURL: "https://api.miracl.net/dvs/register"
        }
    }
};
