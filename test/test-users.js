import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Users init", function () {
    it("should fail without compliant user storage", function () {
        expect(function () {
            var config = testData.init();
            config.userStorage = {};
            var client = new Client(config);
        }).to.throw("Invalid user storage object");
    });
});

describe("Users loadData", function () {
    it("should load user storage data", function () {
        var config = testData.init();
        var client = new Client(config);

        expect(client.users.exists("test@example.com")).to.be.false;

        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            }
        ]));
        client.users.loadData();

        expect(client.users.exists("test@example.com")).to.be.true;
    });

    it("should sort identities by last used timestamp", function () {
        var config = testData.init();

        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId": "test1@example.com",
                "customerId": "projectID",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId1",
                "lastUsed": 30
            },
            {
                "userId": "test2@example.com",
                "customerId": "projectID",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId2",
                "lastUsed": 29
            },
            {
                "userId": "test3@example.com",
                "customerId": "projectID",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId3",
                "lastUsed": 31
            }
        ]));

        var client = new Client(config);

        expect(client.users.data[0].userId).to.equal("test2@example.com");
        expect(client.users.data[1].userId).to.equal("test1@example.com");
        expect(client.users.data[2].userId).to.equal("test3@example.com");
    });
});

describe("Users write", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should add new user data", function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(client.users.exists("test@example.com")).to.be.true;
    });

    it("should update user data", function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(client.users.exists("test@example.com")).to.be.true;

        client.users.write("test@example.com", { state: "REVOKED" });
        expect(client.users.get("test@example.com", "state")).to.equal("REVOKED");
    });

    it("should update only identities for the current customer", function () {
        var otherCustomerData = {
            userId: "test@example.com",
            customerId: "anotherProjectID",
            state: "ACTIVATED",
            mpinId: "exampleMpinId"
        };
        client.users.data = [otherCustomerData];

        client.users.write("test@example.com", { state: "REVOKED" });

        expect(client.users.data[0]).to.deep.equal(otherCustomerData);
    });

    it("should not store sensitive data", function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED",
            csHex: "testCsHex",
            regOTT: "testRegOTT"
        });

        expect(client.users.get("test@example.com", "csHex")).to.equal("");
        expect(client.users.get("test@example.com", "regOTT")).to.equal("");
    });

    it("should add a created timestamp for new identity", function () {
        var beforeCreate = Math.floor(Date.now() / 1000);

        client.users.write("timestamp@example.com", {
            mpinId: "timestampMpinId",
            state: "ACTIVATED"
        });

        expect(client.users.get("timestamp@example.com", "created")).to.exist;
        expect(client.users.get("timestamp@example.com", "created")).to.be.at.least(beforeCreate);
        expect(client.users.get("timestamp@example.com", "created")).to.be.at.most(Math.ceil(Date.now() / 1000));
    });
});

describe("Users exists", function () {
    var client;

    before(function () {
        var config = testData.init();
        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherProjectID",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        client = new Client(config);
    });

    it("should return true for existing user", function () {
        expect(client.users.exists("test@example.com")).to.be.true;
    });

    it("should return false for missing user", function () {
        expect(client.users.exists("missing@example.com")).to.be.false;
    });

    it("should check only identities for the current customer", function () {
        expect(client.users.exists("another.customer@example.com")).to.be.false;
    });
});

describe("Users list", function () {
    var client;

    before(function () {
        var config = testData.init();
        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"test2@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId2"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherProjectID",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        client = new Client(config);
    });

    it("should return a list of users", function () {
        var list = client.users.list();
        expect(list["test@example.com"]).to.equal("ACTIVATED");
        expect(list["test2@example.com"]).to.equal("ACTIVATED");
    });

    it("should list only identities for the current customer", function () {
        var list = client.users.list();
        expect(list["another.customer@example.com"]).to.be.undefined;
    });
});

describe("Users remove", function () {
    var client, config;

    beforeEach(function () {
        config = testData.init()
        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherProjectID",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId",
                "csHex":"anotherTestCsHex"
            },
            {
                "userId":"test@example.com",
                "customerId":"anotherProjectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId2",
                "csHex":"testCsHex2"
            },
        ]));
        client = new Client(config);
    });

    it("should remove an user", function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(client.users.exists("test@example.com")).to.be.true;

        var storeSpy = sinon.spy(client.users, "store");

        client.users.remove("test@example.com");
        expect(client.users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;
    });

    it("should do nothing with non existing user", function () {
        var storeSpy = sinon.spy(client.users, "store");

        client.users.remove("missing@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user for another customer", function () {
        var storeSpy = sinon.spy(client.users, "store");

        client.users.remove("another.customer@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user with the same id for another customer", function () {
        var storeSpy = sinon.spy(client.users, "store");

        client.users.remove("test@example.com");
        expect(client.users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;

        var userStorageData = JSON.parse(config.userStorage.getItem("mfa"));

        expect(userStorageData[1].userId).to.equal("test@example.com");
        expect(userStorageData[1].customerId).to.equal("anotherProjectID");
    });

    afterEach(function () {
        client.users.store.restore && client.users.store.restore();
    })
});

describe("Users get", function () {
    var client;

    before(function () {
        var config = testData.init();
        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherProjectID",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        client = new Client(config);
    });

    it("should fetch a property of the user", function () {
        expect(client.users.get("test@example.com", "mpinId")).to.equal("exampleMpinId");
    });

    it("should return undefined for missing user", function () {
        expect(client.users.get("missing@example.com", "mpinId")).to.be.undefined;
    });

    it("should check only identities for the current customer", function () {
        expect(client.users.get("another.customer@example.com", "mpinId")).to.be.undefined;
    });

    it("should fetch all user data if a property is not requested", function () {
        var userData = client.users.get("test@example.com");
        expect(userData.customerId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("ACTIVATED");
        expect(userData.userId).to.equal("test@example.com");
    });
});

describe("Users updateLastUsed", function () {
    var client, config;

    beforeEach(function () {
        config = testData.init();
        config.userStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            }
        ]));
        client = new Client(config);
    });

    it("should set last used timestamp", function () {
        var currentTime = new Date().getTime();
        client.users.updateLastUsed("test@example.com");
        expect(client.users.get("test@example.com", "lastUsed")).to.be.least(currentTime);
    });

    it("should write updated data to user storage", function () {
        var currentTime = new Date().getTime();
        client.users.updateLastUsed("test@example.com");
        expect(JSON.parse(config.userStorage.getItem("mfa"))[0].lastUsed).to.be.least(currentTime);
    });
});

describe("Users store", function () {
    var client, config;

    before(function () {
        config = testData.init();
        client = new Client(config);
    });

    it("should write identity data to user storage", function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });

        client.users.store();

        var userData = JSON.parse(config.userStorage.getItem("mfa"))[0];

        expect(userData.customerId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("ACTIVATED");
        expect(userData.userId).to.equal("test@example.com");
    });
});
