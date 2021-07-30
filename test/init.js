// In memory storage for users
import storage from "./storage.js";

// Reusable test data
global.testData = {
    init: function () {
        return {
            server: "http://server.com",
            projectId: "projectID",
            seed: "hexSeed",
            defaultPinLength: 4,
            userStorage: new storage(),
            oidc: {
                client_id: "testClientID"
            }
        };
    },
    settings: function () {
        return {
            dtaUrl: "https://api.miracl.net",
            registerURL: "https://api.miracl.net/register/user",
            signatureURL: "https://api.miracl.net/signature",
            mpinAuthServerURL: "https://api.miracl.net/rps",
            dvsRegURL: "https://api.miracl.net/dvs/register",
            pass1URL: "https://api.miracl.net/rps/pass1",
            pass2URL: "https://api.miracl.net/rps/pass2"
        };
    }
};
