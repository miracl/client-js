if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
    var inits = require("./init");
}

describe("Mfa Users loadData", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should load localStorage data", function () {
        expect(mfa.users.exists("test@example.com")).to.be.false;

        localStorage.setItem("mfa", JSON.stringify([
            {
                "userId":"test@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            }
        ]));
        mfa.users.loadData();

        expect(mfa.users.exists("test@example.com")).to.be.true;
    });
});

describe("Mfa Users add", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should add user", function () {
        userId = "test@example.com";
        userData = {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        };
        mfa.users.add("test@example.com", userData);
        expect(mfa.users.exists(userId)).to.be.true;
    });
});

describe("Mfa Users suitableFor", function() {
    var mfa;

    beforeEach(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should return True with user.state Activated for startRegistration", function () {
        mfa.users.add("test@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        });
        expect(mfa.users.suitableFor("test@example.com", "start")).to.be.true;
    });

    it("should return True with user.state Activated for confirmRegistration", function () {
        mfa.users.add("test@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        });
        expect(mfa.users.suitableFor("test@example.com", "confirm")).to.be.true;
    });

    it("should return False with invalid operation", function () {
        mfa.users.add("test@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        });
        expect(mfa.users.suitableFor("test@example.com", "invalid")).to.be.false;
    });

    it("should return True with user.state Invalid for startRegistration", function () {
        mfa.users.add("invalid@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "INVALID"
        });
        expect(mfa.users.suitableFor("invalid@example.com", "start")).to.be.true;
    });

    it("should return False with user.state Invalid for confirmRegistration", function () {
        mfa.users.add("invalid@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "INVALID"
        });
        expect(mfa.users.suitableFor("invalid@example.com", "confirm")).to.be.false;
    });

    it("should return False with user.state Invalid for finishRegistration", function () {
        mfa.users.add("invalid@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "INVALID"
        });
        expect(mfa.users.suitableFor("invalid@example.com", "finish")).to.be.false;
    });

    it("should return True with user.state Started for confirmRegistration", function () {
        mfa.users.add("started@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "STARTED"
        });
        expect(mfa.users.suitableFor("started@example.com", "confirm")).to.be.true;
    });

    it("should return False with missingUser for finishRegistration", function () {
        expect(mfa.users.suitableFor("missing@example.com", "finish")).to.be.false;
    });

    it("should return False with missingUser for confirmRegistration", function () {
        expect(mfa.users.suitableFor("missing@example.com", "confirm")).to.be.false;
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
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId",
                "csHex":"anotherTestCsHex"
            }
        ]));
        mfa = new Mfa(inits.testData.init);
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
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            },
            {
                "userId":"test2@example.com",
                "customerId":"customerId",
                "state":"ACTIVATED",
                "mpinId":"exampleMpinId2",
                "csHex":"testCsHex2"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId",
                "csHex":"anotherTestCsHex"
            }
        ]));
        mfa = new Mfa(inits.testData.init);
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

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should remove an user", function () {
        mfa.users.add("test@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        });
        expect(mfa.users.exists("test@example.com")).to.be.true;

        var storeSpy = sinon.spy(mfa.users, "store");
        mfa.users.delete("test@example.com");
        expect(mfa.users.exists("test@example.com")).to.be.false;
        expect(storeSpy.calledOnce).to.be.true;
    });
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
                "mpinId":"exampleMpinId",
                "csHex":"testCsHex"
            },
            {
                "userId":"another.customer@example.com",
                "customerId":"anotherCustomerId",
                "state":"ACTIVATED",
                "mpinId":"anotherExampleMpinId",
                "csHex":"anotherTestCsHex"
            }
        ]));
        mfa = new Mfa(inits.testData.init);
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

describe("Mfa Users store", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should write identity data to localStorage", function () {
        mfa.users.add("test@example.com", {
            mpinId: "exampleMpinId",
            csHex: "testCsHex",
            state: "ACTIVATED"
        });

        mfa.users.store();

        expect(JSON.parse(localStorage.getItem("mfa"))[0]).to.deep.equal({
            "csHex": "testCsHex",
            "customerId": "customerId",
            "mpinId": "exampleMpinId",
            "state": "ACTIVATED",
            "userId": "test@example.com"
        });
    });
});
