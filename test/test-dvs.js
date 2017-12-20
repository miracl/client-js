if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client generateSignKeypair", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return private and public key", function () {
        var keypair = mfa.generateSignKeypair();
        expect(keypair.privateKey).to.exist;
        expect(keypair.publicKey).to.exist;
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "GET_DVS_KEYPAIR").returns(-1);

        expect(function () {
            mfa.generateSignKeypair();
        }).to.throw("CryptoError");

        mfa.mpin.GET_DVS_KEYPAIR.restore();
    });
});

describe("Mfa Client _generateSignClientSecret", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return the modified client secret", function () {
        sinon.stub(mfa.mpin, "GET_G1_MULTIPLE").returns(0);

        expect(mfa._generateSignClientSecret("privateKey", "0f")).to.equal("0f");

        mfa.mpin.GET_G1_MULTIPLE.restore();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "GET_G1_MULTIPLE").returns(-1);

        expect(function () {
            mfa._generateSignClientSecret("privateKey", "secret");
        }).to.throw("CryptoError");

        mfa.mpin.GET_G1_MULTIPLE.restore();
    });
});

describe("Mfa Client _getSignMpinId", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should combine the MPIN ID with the public key", function () {
        expect(mfa._getSignMpinId("0f", "0f")).to.equal("0f0f");
    });
});

describe("Mfa Client createSigningIdentity", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should create identity ready for signing", function () {
        sinon.stub(mfa, "_addShares").returns("secret");
        sinon.stub(mfa, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(mfa, "_getSignMpinId").returns("signMpinId");
        sinon.stub(mfa, "_calculateMPinToken").returns("token");

        mfa.createSigningIdentity("test@example.com", "mpinId", "share1Hex", "share2Hex", { privateKey: "private", publicKey: "public" }, 1234);

        expect(mfa.users.get("test@example.com", "mpinId")).to.equal("mpinId");
        expect(mfa.users.get("test@example.com", "publicKey")).to.equal("public");
        expect(mfa.users.get("test@example.com", "token")).to.equal("token");
        expect(mfa.users.get("test@example.com", "state")).to.equal("REGISTERED");

        mfa._addShares.restore();
        mfa._generateSignClientSecret.restore();
        mfa._getSignMpinId.restore();
        mfa._calculateMPinToken.restore();
    });
});

describe("Mfa Client signMessage", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return U and V", function () {
        sinon.stub(mfa.mpin, "CLIENT").returns(0);

        var result = mfa.signMessage("test@example.com", "1234", "message", "timestamp");

        expect(result.U).to.equal("")
        expect(result.V).to.equal("")

        mfa.mpin.CLIENT.restore();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "CLIENT").returns(-1);

        expect(function () {
            mfa.signMessage("test@example.com", "1234", "message", "timestamp");
        }).to.throw("CryptoError");

        mfa.mpin.CLIENT.restore();
    });
});
