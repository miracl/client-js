// Mock local storage
global.LocalStorage = function () {
    this.storage = {};
};

global.LocalStorage.prototype.setItem = function (key, value) {
    this.storage[key] = value || '';
};

global.LocalStorage.prototype.getItem = function (key) {
    return this.storage[key] ? this.storage[key] : null;
};

global.LocalStorage.prototype.removeItem = function (key) {
    delete this.storage[key];
};

global.LocalStorage.prototype.clear = function (key) {
    this.storage = {};
};

// Load the crypto library
global.CTX = require("@miracl/crypto-js");

// Reusable test data
global.testData = {
    init: function () {
        return {
            server: "http://server.com",
            customerId: "customerId",
            seed: "hexSeed",
            defaultPinLength: 4,
            userStorage: new LocalStorage()
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
