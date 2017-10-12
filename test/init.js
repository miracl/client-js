if (typeof require !== 'undefined') {
    var fs = require("fs");
    var vm = require("vm");
    var paths, code;

    // Mock local storage
    var LocalStorage = require('node-localstorage').LocalStorage;
    global.localStorage = new LocalStorage('./localStorageTemp');

    global.CTX = require("milagro-crypto-js");
}

var inits = function() {
    var testData = {};

    testData.userId = "test@example.com";

    testData.init = {
        server: "http://server.com",
        customerId: "customerId",
        seed: "hexSeed"
    };

    testData.settings = {
        certivoxURL: "https://miracl.com",
        dtaUrl: "https://api.miracl.net",
        registerURL: "https://api.miracl.net/register/user",
        signatureURL: "https://api.miracl.net/signature",
        mpinAuthServerURL: "https://api.miracl.net/rps"
    };

    return {
        testData: testData
    }
}();

if (typeof module !== "undefined" && typeof module.exports !== "undefined")
    module.exports = inits;
else
    window.inits = inits;
