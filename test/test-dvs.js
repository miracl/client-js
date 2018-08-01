if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client registerDvs", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should go through the DVS registration flow", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startAuthenticationStub = sinon.stub(mfa, "startAuthentication").yields(true);
        var finishAuthenticationStub = sinon.stub(mfa, "finishAuthentication").yields(true);

        mfa.registerDvs("test@example.com", "1234", function (result) {
            expect(startAuthenticationStub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        }, function (err) {
            throw new Error(err);
        });

        mfa.init.restore && mfa.init.restore();
        mfa.startAuthentication.restore && mfa.startAuthentication.restore();
        mfa.finishAuthentication.restore && mfa.finishAuthentication.restore();
    });

});

describe("Mfa Client _renewDvsSecret", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should create a signing identity", function (done) {
        var getDvsSecret1Stub = sinon.stub(mfa, "_getDvsSecret1").yields(true);
        var getDvsSecret2Stub = sinon.stub(mfa, "_getDvsSecret2").yields(true);
        var createSigningIdentityStub = sinon.stub(mfa, "createSigningIdentity").returns(true);

        mfa._renewDvsSecret("test@example.com", "1234", {token: "token", curve: "curve"}, function () {
            expect(getDvsSecret1Stub.calledOnce).to.be.true;
            expect(getDvsSecret2Stub.calledOnce).to.be.true;
            expect(createSigningIdentityStub.calledOnce).to.be.true;
            done();
        }, function (err) {
            throw new Error(err);
        });
    });

    it("should return error if _getDvsSecret1 fails", function (done) {
        sinon.stub(mfa, "init").yields(true);
        sinon.stub(mfa, "_getDvsSecret1").callsArgWith(3, { error: true });

        mfa._renewDvsSecret("test@example.com", "1234", {token: "token", curve: "curve"}, function () {
            throw new Error();
        }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if _getDvsSecret2 fails", function (done) {
        sinon.stub(mfa, "init").yields(true);
        sinon.stub(mfa, "_getDvsSecret1").yields(true);
        sinon.stub(mfa, "_getDvsSecret2").callsArgWith(2, { error: true });

        mfa._renewDvsSecret("test@example.com", "1234", {token: "token", curve: "curve"}, function () {
            throw new Error();
        }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if createSigningIdentity fails", function (done) {
        sinon.stub(mfa, "init").yields(true);
        sinon.stub(mfa, "_getDvsSecret1").yields(true);
        sinon.stub(mfa, "_getDvsSecret2").yields(true);
        sinon.stub(mfa, "createSigningIdentity").throws({ error: true });

        mfa._renewDvsSecret("test@example.com", "1234", {token: "token", curve: "curve"}, function () {
            throw new Error();
        }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    afterEach(function () {
        mfa.init.restore && mfa.init.restore();
        mfa._getDvsSecret1.restore && mfa._getDvsSecret1.restore();
        mfa._getDvsSecret2.restore && mfa._getDvsSecret2.restore();
        mfa.createSigningIdentity.restore && mfa.createSigningIdentity.restore();
    })
});

describe("Mfa Client _getDvsSecret1", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(mfa, "request").yields({}, null);

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (data) {
            throw new Error(data);
        }, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback with data", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (cs1Data) {
            expect(cs1Data).to.exist;
            expect(cs1Data).to.have.property("success");
            expect(cs1Data.success).to.be.true;
            done();
        }, function(err) {
            throw new Error(err);
        });
    });

    it("should make request to dvs register endpoint", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/dvs/register");
            done();
        }, function(err) {
            throw new Error(err);
        });
    });

    it("should make request with public key and device name", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getDeviceName").returns("device");

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].data).to.deep.equal({ publicKey: "public", deviceName: "device", dvsRegisterToken: "dvsRegisterToken" });
            done();
        }, function(err) {
            throw new Error(err);
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _getDvsSecret2", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(mfa, "request").yields({}, null);

        mfa._getDvsSecret2({ cs2url: "https://test/clientSecret" }, function (data) {
            throw new Error(data);
        }, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback with data", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret2({ cs2url: "https://test/clientSecret" }, function (cs2Data) {
            expect(cs2Data).to.exist;
            expect(cs2Data).to.have.property("success");
            expect(cs2Data.success).to.be.true;
            done();
        }, function(err) {
            throw new Error(err);
        });
    });

    it("should make request with passed params", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret2({ cs2url: "https://test/clientSecret" }, function (cs2Data) {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("https://test/clientSecret");
            done();
        }, function(err) {
            throw new Error(err);
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
    });
});

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

        mfa.createSigningIdentity("test@example.com", "dvsMpinId", "dtas", "share1Hex", "share2Hex", { privateKey: "private", publicKey: "public" }, 1234);

        expect(mfa.dvsUsers.get("test@example.com", "mpinId")).to.equal("dvsMpinId");
        expect(mfa.dvsUsers.get("test@example.com", "publicKey")).to.equal("public");
        expect(mfa.dvsUsers.get("test@example.com", "token")).to.equal("token");
        expect(mfa.dvsUsers.get("test@example.com", "state")).to.equal("REGISTERED");

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

        mfa.signMessage("test@example.com", "1234", "message", "timestamp", function (result) {
            expect(result.U).to.equal("")
            expect(result.V).to.equal("")
        }, function (err) {
            throw new Error(err);
        });

        mfa.mpin.CLIENT.restore();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "CLIENT").returns(-1);

        mfa.signMessage("test@example.com", "1234", "message", "timestamp", function (result) {
            throw new Error(result);
        }, function (err) {
            expect(err.name).to.equal("CryptoError");
        });

        mfa.mpin.CLIENT.restore();
    });
});
