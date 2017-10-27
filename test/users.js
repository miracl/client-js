if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
}

describe("Mfa Users loadData", function () {
    var mfa;

    beforeEach(function () {
        localStorage.clear();
        mfa = new Mfa(testData.init);
    });

    it("should load localStorage data", function () {
        expect(mfa.users.exists("test@example.com")).to.be.false;

        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            }
        ]));
        mfa.users.loadData();

        expect(mfa.users.exists("test@example.com")).to.be.true;
    });

    it("should sort identities by last used timestamp", function () {
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId": "test1@example.com",
                "customerId": "customerId",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId1",
                "lastUsed": 30
            },
            {
                "userId": "test2@example.com",
                "customerId": "customerId",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId2",
                "lastUsed": 29
            },
            {
                "userId": "test3@example.com",
                "customerId": "customerId",
                "state": "ACTIVATED",
                "mpinId": "exampleMpinId3",
                "lastUsed": 31
            }
        ]));

        mfa.users.loadData();

        expect(mfa.users.data[0].userId).to.equal("test2@example.com");
        expect(mfa.users.data[1].userId).to.equal("test1@example.com");
        expect(mfa.users.data[2].userId).to.equal("test3@example.com");
    });
});

describe("Mfa Users write", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(testData.init);
    });

    it("should add new user data", function () {
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(mfa.users.exists("test@example.com")).to.be.true;
    });

    it("should update user data", function () {
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(mfa.users.exists("test@example.com")).to.be.true;

        mfa.users.write("test@example.com", { state: "REVOKED" });
        expect(mfa.users.get("test@example.com", "state")).to.equal("REVOKED");
    });

    it("should update only identities for the current customer", function () {
        var otherCustomerData = {
            userId: "test@example.com",
            customerId: "anotherCustomerId",
            state: "ACTIVATED",
            mpinId: "exampleMpinId"
        };
        mfa.users.data = [otherCustomerData];

        mfa.users.write("test@example.com", { state: "REVOKED" });

        expect(mfa.users.data[0]).to.deep.equal(otherCustomerData);
    });

    it("should not store sensitive data", function () {
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED",
            csHex: "testCsHex",
            regOTT: "testRegOTT"
        });

        expect(mfa.users.get("test@example.com", "csHex")).to.equal("");
        expect(mfa.users.get("test@example.com", "regOTT")).to.equal("");
    });
});

describe("Mfa Users exists", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        mfa = new Mfa(testData.init);
    });

    it("should return true for existing user", function () {
        expect(mfa.users.exists("test@example.com")).to.be.true;
    });

    it("should return false for missing user", function () {
        expect(mfa.users.exists("missing@example.com")).to.be.false;
    });

    it("should check only identities for the current customer", function () {
        expect(mfa.users.exists("another.customer@example.com")).to.be.false;
    });
});

describe("Mfa Users list", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"test2@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId2"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        mfa = new Mfa(testData.init);
    });

    it("should return a list of users", function () {
        var list = mfa.users.list();
        expect(list["test@example.com"]).to.equal("ACTIVATED");
        expect(list["test2@example.com"]).to.equal("ACTIVATED");
    });

    it("should list only identities for the current customer", function () {
        var list = mfa.users.list();
        expect(list["another.customer@example.com"]).to.be.undefined;
    });
});

describe("Mfa Users delete", function () {
    var mfa;

    beforeEach(function () {
        localStorage.clear();
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId",
                "csHex":"anotherTestCsHex"
            },
            {
                "userId":"test@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId2",
                "csHex":"testCsHex2"
            },
        ]));
        mfa = new Mfa(testData.init);
    });

    it("should remove an user", function () {
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
        expect(mfa.users.exists("test@example.com")).to.be.true;

        var storeSpy = sinon.spy(mfa.users, "store");

        mfa.users.delete("test@example.com");
        expect(mfa.users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;
    });

    it("should do nothing with non existing user", function () {
        var storeSpy = sinon.spy(mfa.users, "store");

        mfa.users.delete("missing@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not delete user for another customer", function () {
        var storeSpy = sinon.spy(mfa.users, "store");

        mfa.users.delete("another.customer@example.com");
        expect(storeSpy.callCount).to.equal(0);
    });

    it("should not delete user with the same id for another customer", function () {
        var storeSpy = sinon.spy(mfa.users, "store");

        mfa.users.delete("test@example.com");
        expect(mfa.users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;

        var localStorageData = JSON.parse(localStorage.getItem("mfa"));

        expect(localStorageData[1].userId).to.equal("test@example.com");
        expect(localStorageData[1].customerId).to.equal("anotherCustomerId");
    });

    afterEach(function () {
        mfa.users.store.restore && mfa.users.store.restore();
    })
});

describe("Mfa Users get", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId"
            }
        ]));
        mfa = new Mfa(testData.init);
    });

    it("should fetch a property of the user", function () {
        expect(mfa.users.get("test@example.com", "mpinId")).to.equal("exampleMpinId");
    });

    it("should return false for missing user", function () {
        expect(mfa.users.get("missing@example.com", "mpinId")).to.be.false;
    });

    it("should check only identities for the current customer", function () {
        expect(mfa.users.get("another.customer@example.com", "mpinId")).to.be.false;
    });
});

describe("Mfa Users updateLastUsed", function () {
    var mfa;

    beforeEach(function () {
        localStorage.clear();
        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId"
            }
        ]));
        mfa = new Mfa(testData.init);
    });

    it("should set last used timestamp", function () {
        var currentTime = new Date().getTime();
        mfa.users.updateLastUsed("test@example.com");
        expect(mfa.users.get("test@example.com", "lastUsed")).to.be.least(currentTime);
    });

    it("should write updated data to localStorage", function () {
        var currentTime = new Date().getTime();
        mfa.users.updateLastUsed("test@example.com");
        expect(JSON.parse(localStorage.getItem("mfa"))[0].lastUsed).to.be.least(currentTime);
    });
});

describe("Mfa Users store", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(testData.init);
    });

    it("should write identity data to localStorage", function () {
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });

        mfa.users.store();

        expect(JSON.parse(localStorage.getItem("mfa"))[0]).to.deep.equal({
            "customerId": "customerId",
            "mpinId": "exampleMpinId",
            "state": "ACTIVATED",
            "userId": "test@example.com"
        });
    });
});
