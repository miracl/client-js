if (typeof require !== 'undefined') {
    // Mock local storage
    var LocalStorage = require('node-localstorage').LocalStorage;
    global.localStorage = new LocalStorage('./localStorageTemp');
}

var inits = function() {
    var testData = {};

    testData.userId = "test@example.com";

    testData.init = {};
    testData.init.server = "http://server.com";
    testData.init.distributor = "mcl";
    testData.init.customerId = "customerId";

    testData.settings = {
        certivoxURL: "https://miracl.com",
        dtaUrl: "https://api.miracl.net",
        registerURL: "https://api.miracl.net/register/user",
        signatureURL: "https://api.miracl.net/signature",
        mpinAuthServerURL: "https://api.miracl.net/rps"
    };

    testData.users = {
        "test@example.com": {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        },
        "invalid@example.com": {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "INVALID"
        },
        "started@example.com": {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "STARTED"
        }
    };

    testData.cs1 = {
        clientSecret: "clientSecretValue"
    };

    testData.cs2 = {
        clientSecretShare: "clientSecretValue"
    };

    return {
        testData: testData
    }
}();

if (typeof module !== "undefined" && typeof module.exports !== "undefined")
    module.exports = inits;
else
    window.inits = inits;
