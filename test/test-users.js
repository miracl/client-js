import Users from "../src/users.js";
import Storage from "./storage.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Users init", function () {
    it("should fail without compliant user storage", function () {
        expect(function () {
            new Users({}, "projectID", "mfa");
        }).to.throw("Invalid user storage object");
    });

    it("should fail without project ID", function () {
        expect(function () {
            new Users(new Storage(), null, "mfa");
        }).to.throw("Project ID must be provided when configuring storage");
    });

    it("should fail without storage key", function () {
        expect(function () {
            new Users(new Storage(), "projectID", null);
        }).to.throw("Storage key must be provided when configuring storage");
    });
});

describe("Users loadData", function () {
    it("should load user storage data", function () {
        var storage = new Storage();
        var users = new Users(storage, "projectID", "mfa");

        expect(users.exists("test@example.com")).to.be.false;

        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            }
        ]));
        users.loadData();

        expect(users.exists("test@example.com")).to.be.true;
    });

    it("should sort identities by last used timestamp", function () {
        var storage = new Storage();

        storage.setItem("mfa", JSON.stringify([
            {
                "userId": "test1@example.com",
                "projectId": "projectID",
                "state": "REGISTERED",
                "mpinId": "exampleMpinId1",
                "lastUsed": 30
            },
            {
                "userId": "test2@example.com",
                "projectId": "projectID",
                "state": "REGISTERED",
                "mpinId": "exampleMpinId2",
                "lastUsed": 29
            },
            {
                "userId": "test3@example.com",
                "projectId": "projectID",
                "state": "REGISTERED",
                "mpinId": "exampleMpinId3",
                "lastUsed": 31
            }
        ]));

        var users = new Users(storage, "projectID", "mfa");

        expect(users.data[0].userId).to.equal("test2@example.com");
        expect(users.data[1].userId).to.equal("test1@example.com");
        expect(users.data[2].userId).to.equal("test3@example.com");
    });
});

describe("Users write", function () {
    var users, storage;

    before(function () {
        storage = new Storage();
        users = new Users(storage, "projectID", "mfa");
    });

    it("should add new user data", function () {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
        expect(users.exists("test@example.com")).to.be.true;
    });

    it("should update user data", function () {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
        expect(users.exists("test@example.com")).to.be.true;

        users.write("test@example.com", { state: "REVOKED" });
        expect(users.get("test@example.com", "state")).to.equal("REVOKED");
    });

    it("should update only identities for the current project", function () {
        var otherProjectData = {
            userId: "test@example.com",
            projectId: "anotherProjectID",
            state: "REGISTERED",
            mpinId: "exampleMpinId"
        };
        users.data = [otherProjectData];

        users.write("test@example.com", { state: "REVOKED" });

        expect(users.data[0]).to.deep.equal(otherProjectData);
    });

    it("should not store sensitive data", function () {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED",
            csHex: "testCsHex",
            regOTT: "testRegOTT"
        });

        expect(users.get("test@example.com", "csHex")).to.equal("");
        expect(users.get("test@example.com", "regOTT")).to.equal("");
    });

    it("should add a created timestamp for new identity", function () {
        var beforeCreate = Math.floor(Date.now() / 1000);

        users.write("timestamp@example.com", {
            mpinId: "timestampMpinId",
            state: "REGISTERED"
        });

        expect(users.get("timestamp@example.com", "created")).to.exist;
        expect(users.get("timestamp@example.com", "created")).to.be.at.least(beforeCreate);
        expect(users.get("timestamp@example.com", "created")).to.be.at.most(Math.ceil(Date.now() / 1000));
    });

    it("should work with identities stored with customerId", function () {
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            }
        ]));

        users.loadData();

        expect(users.get("test@example.com", "state")).to.equal("REGISTERED");

        users.write("test@example.com", { state: "REVOKED" });
        expect(users.get("test@example.com", "state")).to.equal("REVOKED");
    });
});

describe("Users exists", function () {
    var users;

    before(function () {
        var storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.project@example.com",
                "projectId":"anotherProjectID",
                "state":"REGISTERED",
                "mpinId":"anotherExampleMpinId"
            },
            {
                "userId":"test2@example.com",
                "customerId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            }
        ]));

        users = new Users(storage, "projectID", "mfa");
    });

    it("should return true for existing user", function () {
        expect(users.exists("test@example.com")).to.be.true;
    });

    it("should return false for missing user", function () {
        expect(users.exists("missing@example.com")).to.be.false;
    });

    it("should check only identities for the current project", function () {
        expect(users.exists("another.project@example.com")).to.be.false;
    });

    it("should work with identities stored with customerId", function () {
        expect(users.exists("test2@example.com")).to.be.true;
    });
});

describe("Users is", function () {
    var users;

    before(function () {
        var storage = new Storage();

        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"test2@example.com",
                "projectId":"projectID",
                "state":"STARTED",
                "mpinId":"anotherExampleMpinId"
            },
            {
                "userId":"test3@example.com",
                "projectId":"projectID",
                "state":"REVOKED",
                "mpinId":"thirdExampleMpinId"
            },
            {
                "userId":"test4@example.com",
                "customerId":"projectID",
                "state":"REGISTERED",
                "mpinId":"fourthExampleMpinId"
            }
        ]));

        users = new Users(storage, "projectID", "mfa");
    });

    it("should check if user is in the provided state", function () {
        expect(users.is("test@example.com", "REGISTERED")).to.be.true;
        expect(users.is("test2@example.com", "STARTED")).to.be.true;
        expect(users.is("test3@example.com", "REVOKED")).to.be.true;
    });

    it("should work with identities stored with customerId", function () {
        expect(users.is("test4@example.com", "REGISTERED")).to.be.true;
    });
});

describe("Users list", function () {
    var users;

    before(function () {
        var storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"test2@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId2"
            },
            {
                "userId":"test3@example.com",
                "customerId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId3"
            },
            {
                "userId":"another.project@example.com",
                "projectId":"anotherProjectID",
                "state":"REGISTERED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        users = new Users(storage, "projectID", "mfa");
    });

    it("should return a list of users", function () {
        var list = users.list();
        expect(list["test@example.com"]).to.equal("REGISTERED");
        expect(list["test2@example.com"]).to.equal("REGISTERED");
    });

    it("should list only identities for the current project", function () {
        var list = users.list();
        expect(list["another.project@example.com"]).to.be.undefined;
    });

    it("should work with identities stored with customerId", function () {
        var list = users.list();
        expect(list["test3@example.com"]).to.equal("REGISTERED");
    });
});

describe("Users remove", function () {
    var users, storage;

    beforeEach(function () {
        storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED"
            },
            {
                "userId":"another.project@example.com",
                "projectId":"anotherProjectID",
                "state":"REGISTERED"
            },
            {
                "userId":"test@example.com",
                "projectId":"anotherProjectID",
                "state":"REGISTERED"
            },
            {
                "userId":"test.customer.id@example.com",
                "customerId":"projectID",
                "state":"REGISTERED"
            }
        ]));

        users = new Users(storage, "projectID", "mfa");
    });

    it("should remove an user", function () {
        expect(users.exists("test@example.com")).to.be.true;

        var storeSpy = sinon.spy(users, "store");

        users.remove("test@example.com");
        expect(users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;
    });

    it("should do nothing with non existing user", function () {
        var storeSpy = sinon.spy(users, "store");

        users.remove("missing@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user for another project", function () {
        var storeSpy = sinon.spy(users, "store");

        users.remove("another.project@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user with the same id for another project", function () {
        var storeSpy = sinon.spy(users, "store");

        users.remove("test@example.com");
        expect(users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;

        var userStorageData = JSON.parse(storage.getItem("mfa"));

        expect(userStorageData[1].userId).to.equal("test@example.com");
        expect(userStorageData[1].projectId).to.equal("anotherProjectID");
    });

    it("should work with identities stored with customerId", function () {
        expect(users.exists("test.customer.id@example.com")).to.be.true;
        users.remove("test.customer.id@example.com");
        expect(users.exists("test.customer.id@example.com")).to.be.false;
    });

    afterEach(function () {
        users.store.restore && users.store.restore();
    })
});

describe("Users get", function () {
    var users;

    before(function () {
        var storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.project@example.com",
                "projectId":"anotherProjectID",
                "state":"REGISTERED",
                "mpinId":"anotherExampleMpinId"
            },
            {
                "userId":"test.customer.id@example.com",
                "customerId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId2"
            },
        ]));
        users = new Users(storage, "projectID", "mfa");
    });

    it("should fetch a property of the user", function () {
        expect(users.get("test@example.com", "mpinId")).to.equal("exampleMpinId");
    });

    it("should return undefined for missing user", function () {
        expect(users.get("missing@example.com", "mpinId")).to.be.undefined;
    });

    it("should check only identities for the current project", function () {
        expect(users.get("another.project@example.com", "mpinId")).to.be.undefined;
    });

    it("should fetch all user data if a property is not requested", function () {
        var userData = users.get("test@example.com");
        expect(userData.projectId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("REGISTERED");
        expect(userData.userId).to.equal("test@example.com");
    });

    it("should work with identities stored with customerId", function () {
        expect(users.get("test.customer.id@example.com", "mpinId")).to.equal("exampleMpinId2");
    });
});

describe("Users updateLastUsed", function () {
    var users, storage;

    beforeEach(function () {
        storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            }
        ]));
        users = new Users(storage, "projectID", "mfa");
    });

    it("should set last used timestamp", function () {
        var currentTime = new Date().getTime();
        users.updateLastUsed("test@example.com");
        expect(users.get("test@example.com", "lastUsed")).to.be.least(currentTime);
    });

    it("should write updated data to user storage", function () {
        var currentTime = new Date().getTime();
        users.updateLastUsed("test@example.com");
        expect(JSON.parse(storage.getItem("mfa"))[0].lastUsed).to.be.least(currentTime);
    });
});

describe("Users store", function () {
    var users, storage;

    before(function () {
        storage = new Storage();
        users = new Users(storage, "projectID", "mfa");
    });

    it("should write identity data to user storage", function () {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });

        users.store();

        var userData = JSON.parse(storage.getItem("mfa"))[0];

        expect(userData.projectId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("REGISTERED");
        expect(userData.userId).to.equal("test@example.com");
    });
});
