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
    }
};
