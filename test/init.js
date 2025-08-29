// In memory storage for users
import storage from "./storage.js";

// Reusable test data
global.testData = {
    init: function () {
        return {
            projectUrl: "https://project.miracl.io",
            projectId: "projectID",
            seed: "hexSeed",
            defaultPinLength: 4,
            userStorage: new storage()
        };
    }
};
