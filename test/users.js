if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
    var inits = require("./init");
}

describe("Mfa Users add", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should add user", function () {
        userId = inits.testData.userId;
        userData = inits.testData.users[userId];
        mfa.users.add(userId, userData);
        expect(mfa.users.exists(userId)).to.be.true;
    });
});

describe("Mfa Users suitableFor", function() {
    var mfa, userData, userId;

    beforeEach(function () {
        var userId;

        localStorage.clear();
        mfa = new Mfa(inits.testData.init);

        // Inject user data
        for (userId in inits.testData.users) {
            if (inits.testData.users.hasOwnProperty(userId)) {
                mfa.users.add(userId, inits.testData.users[userId]);
            }
        }
    });

    it("should return True with user.state Activated for startRegistration", function () {
        expect(mfa.users.suitableFor("test@example.com", "start")).to.be.true;
    });

    it("should return True with user.state Activated for confirmRegistration", function () {
        expect(mfa.users.suitableFor("test@example.com", "confirm")).to.be.true;
    });

    it("should return True with user.state Invalid for startRegistration", function () {
        expect(mfa.users.suitableFor("invalid@example.com", "start")).to.be.true;
    });

    it("should return False with user.state Invalid for confirmRegistration", function () {
        expect(mfa.users.suitableFor("invalid@example.com", "confirm")).to.be.false;
    });

    it("should return False with user.state Invalid for finishRegistration", function () {
        expect(mfa.users.suitableFor("invalid@example.com", "finish")).to.be.false;
    });

    it("should return True with user.state Started for confirmRegistration", function () {
        expect(mfa.users.suitableFor("started@example.com", "confirm")).to.be.true;
    });

    it("should return False with missingUser for finishRegistration", function () {
        expect(mfa.users.suitableFor("missing@example.com", "finish")).to.be.false;
    });

    it("should return False with missingUser for confirmRegistration", function () {
        expect(mfa.users.suitableFor("missing@example.com", "confirm")).to.be.false;
    });

    it("should return False with invalid operation", function () {
        expect(mfa.users.suitableFor("test@example.com", "invalid")).to.be.false;
    });
});

describe("Mfa Users exists", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should return false for missing user", function () {
        expect(mfa.users.exists("missing@example.com")).to.be.false;
    });

    it("should return true for existing user", function () {
        userId = inits.testData.userId;
        var userData = inits.testData.users[userId];
        mfa.users.add(userId, userData);
        expect(mfa.users.exists(userId)).to.be.true;
    });
});

describe("Mfa Users list", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
        var userData = inits.testData.users[inits.testData.userId];
        mfa.users.add(inits.testData.userId, userData);
    });

    it("should return a list of users", function () {
        var list = mfa.users.list();
        expect(list[inits.testData.userId]).to.equal("ACTIVATED");
    });
});

describe("Mfa Users delete", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should remove an user", function () {
        mfa.users.delete(inits.testData.userId);
        expect(mfa.users.exists(inits.testData.userId)).to.be.false;
    });
});

describe("Mfa Users get", function () {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
        var userData = inits.testData.users[inits.testData.userId];
        mfa.users.add(inits.testData.userId, userData);
    });

    it("should fetch a property of the user", function () {
        expect(mfa.users.get(inits.testData.userId, "mpinId")).to.equal("exampleMpinId");
    });

    it("should return false for missing user", function () {
        expect(mfa.users.get("missing@example.com", "mpinId")).to.be.false;
    });
});
