import { afterEach, before, beforeEach, describe, it } from "mocha";
import { expect } from "chai";
import sinon from "sinon";
import Storage from "./storage.js";
import Users from "../src/users.js";

describe("Users init", () => {
    it("should fail without compliant user storage", () => {
        expect(() => {
            new Users({}, "projectID", "mfa");
        }).to.throw("Invalid user storage object");
    });

    it("should fail without project ID", () => {
        expect(() => {
            new Users(new Storage(), null, "mfa");
        }).to.throw("Project ID must be provided when configuring storage");
    });

    it("should fail without storage key", () => {
        expect(() => {
            new Users(new Storage(), "projectID", null);
        }).to.throw("Storage key must be provided when configuring storage");
    });
});

describe("Users loadData", () => {
    it("should load user storage data", () => {
        const storage = new Storage();
        const users = new Users(storage, "projectID", "mfa");

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

    it("should sort identities by last used timestamp", () => {
        const storage = new Storage();

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

        const users = new Users(storage, "projectID", "mfa");

        expect(users.data[0].userId).to.equal("test2@example.com");
        expect(users.data[1].userId).to.equal("test1@example.com");
        expect(users.data[2].userId).to.equal("test3@example.com");
    });
});

describe("Users write", () => {
    let users, storage;

    before(() => {
        storage = new Storage();
        users = new Users(storage, "projectID", "mfa");
    });

    it("should add new user data", () => {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
        expect(users.exists("test@example.com")).to.be.true;
    });

    it("should update user data", () => {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
        expect(users.exists("test@example.com")).to.be.true;

        users.write("test@example.com", { state: "REVOKED" });
        expect(users.get("test@example.com", "state")).to.equal("REVOKED");
    });

    it("should update only identities for the current project", () => {
        const otherProjectData = {
            userId: "test@example.com",
            projectId: "anotherProjectID",
            state: "REGISTERED",
            mpinId: "exampleMpinId"
        };
        users.data = [otherProjectData];

        users.write("test@example.com", { state: "REVOKED" });

        expect(users.data[0]).to.deep.equal(otherProjectData);
    });

    it("should not store sensitive data", () => {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED",
            csHex: "testCsHex",
            regOTT: "testRegOTT"
        });

        expect(users.get("test@example.com", "csHex")).to.equal("");
        expect(users.get("test@example.com", "regOTT")).to.equal("");
    });

    it("should add a created timestamp for new identity", () => {
        const beforeCreate = Math.floor(Date.now() / 1000);

        users.write("timestamp@example.com", {
            mpinId: "timestampMpinId",
            state: "REGISTERED"
        });

        expect(users.get("timestamp@example.com", "created")).to.exist;
        expect(users.get("timestamp@example.com", "created")).to.be.at.least(beforeCreate);
        expect(users.get("timestamp@example.com", "created")).to.be.at.most(Math.ceil(Date.now() / 1000));
    });

    it("should work with identities stored with customerId", () => {
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

describe("Users exists", () => {
    let users;

    before(() => {
        const storage = new Storage();
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

    it("should return true for existing user", () => {
        expect(users.exists("test@example.com")).to.be.true;
    });

    it("should return false for missing user", () => {
        expect(users.exists("missing@example.com")).to.be.false;
    });

    it("should check only identities for the current project", () => {
        expect(users.exists("another.project@example.com")).to.be.false;
    });

    it("should work with identities stored with customerId", () => {
        expect(users.exists("test2@example.com")).to.be.true;
    });
});

describe("Users is", () => {
    let users;

    before(() => {
        const storage = new Storage();

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

    it("should check if user is in the provided state", () => {
        expect(users.is("test@example.com", "REGISTERED")).to.be.true;
        expect(users.is("test2@example.com", "STARTED")).to.be.true;
        expect(users.is("test3@example.com", "REVOKED")).to.be.true;
    });

    it("should work with identities stored with customerId", () => {
        expect(users.is("test4@example.com", "REGISTERED")).to.be.true;
    });
});

describe("Users list", () => {
    let users;

    before(() => {
        const storage = new Storage();
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

    it("should return a list of users", () => {
        const list = users.list();
        expect(list["test@example.com"]).to.equal("REGISTERED");
        expect(list["test2@example.com"]).to.equal("REGISTERED");
    });

    it("should list only identities for the current project", () => {
        const list = users.list();
        expect(list["another.project@example.com"]).to.be.undefined;
    });

    it("should work with identities stored with customerId", () => {
        const list = users.list();
        expect(list["test3@example.com"]).to.equal("REGISTERED");
    });
});

describe("Users count", () => {
    let users;

    it("should return a count of users", () => {
        const storage = new Storage();
        storage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "projectId":"projectID",
                "state":"REGISTERED",
                "mpinId":"exampleMpinId"
            }
        ]));
        users = new Users(storage, "projectID", "mfa");

        expect(users.count()).to.equal(1);
    });

    it("should return zero on empty storage", () => {
        const storage = new Storage();
        users = new Users(storage, "projectID", "mfa");

        expect(users.count()).to.equal(0);
    });

    it("should count only identities for the current project", () => {
        const storage = new Storage();
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
            }
        ]));
        users = new Users(storage, "projectID", "mfa");

        expect(users.count()).to.equal(1);
    });
});

describe("Users remove", () => {
    let users, storage;

    beforeEach(() => {
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

    it("should remove an user", () => {
        expect(users.exists("test@example.com")).to.be.true;

        const storeSpy = sinon.spy(users, "store");

        users.remove("test@example.com");
        expect(users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;
    });

    it("should do nothing with non existing user", () => {
        const storeSpy = sinon.spy(users, "store");

        users.remove("missing@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user for another project", () => {
        const storeSpy = sinon.spy(users, "store");

        users.remove("another.project@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not remove user with the same id for another project", () => {
        const storeSpy = sinon.spy(users, "store");

        users.remove("test@example.com");
        expect(users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;

        const userStorageData = JSON.parse(storage.getItem("mfa"));

        expect(userStorageData[1].userId).to.equal("test@example.com");
        expect(userStorageData[1].projectId).to.equal("anotherProjectID");
    });

    it("should work with identities stored with customerId", () => {
        expect(users.exists("test.customer.id@example.com")).to.be.true;
        users.remove("test.customer.id@example.com");
        expect(users.exists("test.customer.id@example.com")).to.be.false;
    });

    afterEach(() => {
        users.store.restore && users.store.restore();
    });
});

describe("Users get", () => {
    let users;

    before(() => {
        const storage = new Storage();
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

    it("should fetch a property of the user", () => {
        expect(users.get("test@example.com", "mpinId")).to.equal("exampleMpinId");
    });

    it("should return undefined for missing user", () => {
        expect(users.get("missing@example.com", "mpinId")).to.be.undefined;
    });

    it("should check only identities for the current project", () => {
        expect(users.get("another.project@example.com", "mpinId")).to.be.undefined;
    });

    it("should fetch all user data if a property is not requested", () => {
        const userData = users.get("test@example.com");
        expect(userData.projectId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("REGISTERED");
        expect(userData.userId).to.equal("test@example.com");
    });

    it("should work with identities stored with customerId", () => {
        expect(users.get("test.customer.id@example.com", "mpinId")).to.equal("exampleMpinId2");
    });
});

describe("Users updateLastUsed", () => {
    let users, storage;

    beforeEach(() => {
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

    it("should set last used timestamp", () => {
        const currentTime = new Date().getTime();
        users.updateLastUsed("test@example.com");
        expect(users.get("test@example.com", "lastUsed")).to.be.least(currentTime);
    });

    it("should write updated data to user storage", () => {
        const currentTime = new Date().getTime();
        users.updateLastUsed("test@example.com");
        expect(JSON.parse(storage.getItem("mfa"))[0].lastUsed).to.be.least(currentTime);
    });
});

describe("Users store", () => {
    let users, storage;

    before(() => {
        storage = new Storage();
        users = new Users(storage, "projectID", "mfa");
    });

    it("should write identity data to user storage", () => {
        users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });

        users.store();

        const userData = JSON.parse(storage.getItem("mfa"))[0];

        expect(userData.projectId).to.equal("projectID");
        expect(userData.mpinId).to.equal("exampleMpinId");
        expect(userData.state).to.equal("REGISTERED");
        expect(userData.userId).to.equal("test@example.com");
    });
});
