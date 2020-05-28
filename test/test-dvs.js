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
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, true);
        var renewDvsSecretStub = sinon.stub(mfa, "_renewDvsSecret").yields(null, true);

        mfa.registerDvs("test@example.com", "1234", "1234", function (err, result) {
            expect(err).to.be.null;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(renewDvsSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fail if authentication fails", function (done) {
        sinon.stub(mfa, "_authentication").yields({ error: true });

        mfa.registerDvs("test@example.com", "1234", "1234", function (err, result) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        mfa._authentication.restore && mfa._authentication.restore();
        mfa._renewDvsSecret.restore && mfa._renewDvsSecret.restore();
    });

});

describe("Mfa Client _renewDvsSecret", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should create a signing identity", function (done) {
        var getDvsSecret1Stub = sinon.stub(mfa, "_getDvsSecret1").yields(null, true);
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null, true);
        var createSigningIdentityStub = sinon.stub(mfa, "_createSigningIdentity").yields(null, true);

        mfa._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.be.null;
            expect(getDvsSecret1Stub.calledOnce).to.be.true;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(createSigningIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should return error if _getDvsSecret1 fails", function (done) {
        sinon.stub(mfa, "_init").yields(null, true);
        sinon.stub(mfa, "_getDvsSecret1").yields({ error: true });

        mfa._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if _getSecret2 fails", function (done) {
        sinon.stub(mfa, "_init").yields(null,true);
        sinon.stub(mfa, "_getDvsSecret1").yields(null, true);
        sinon.stub(mfa, "_getSecret2").yields({ error: true }, null);

        mfa._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if createSigningIdentity fails", function (done) {
        sinon.stub(mfa, "_init").yields(true);
        sinon.stub(mfa, "_getDvsSecret1").yields(null, true);
        sinon.stub(mfa, "_getSecret2").yields(null, true);
        sinon.stub(mfa, "_createSigningIdentity").yields({ error: true });

        mfa._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    afterEach(function () {
        mfa._init.restore && mfa._init.restore();
        mfa._getDvsSecret1.restore && mfa._getDvsSecret1.restore();
        mfa._getSecret2.restore && mfa._getSecret2.restore();
        mfa._createSigningIdentity.restore && mfa._createSigningIdentity.restore();
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

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback with data", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, cs1Data) {
            expect(err).to.be.null;
            expect(cs1Data).to.exist;
            expect(cs1Data).to.have.property("success");
            expect(cs1Data.success).to.be.true;
            done();
        });
    });

    it("should make request to dvs register endpoint", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/dvs/register");
            done();
        });
    });

    it("should make request with public key and device name", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getDeviceName").returns("device");

        mfa._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].data).to.deep.equal({ publicKey: "public", deviceName: "device", dvsRegisterToken: "dvsRegisterToken" });
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _generateSignKeypair", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return private and public key", function () {
        var keypair = mfa._generateSignKeypair();
        expect(keypair.privateKey).to.exist;
        expect(keypair.publicKey).to.exist;
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.crypto().MPIN, "GET_DVS_KEYPAIR").returns(-1);

        expect(function () {
            mfa._generateSignKeypair();
        }).to.throw("CryptoError");

        mfa.crypto().MPIN.GET_DVS_KEYPAIR.restore();
    });
});

describe("Mfa Client _generateSignClientSecret", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return the modified client secret", function () {
        sinon.stub(mfa.crypto().MPIN, "GET_G1_MULTIPLE").returns(0);

        expect(mfa._generateSignClientSecret("privateKey", "0f")).to.equal("0f");

        mfa.crypto().MPIN.GET_G1_MULTIPLE.restore();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.crypto().MPIN, "GET_G1_MULTIPLE").returns(-1);

        expect(function () {
            mfa._generateSignClientSecret("privateKey", "secret");
        }).to.throw("CryptoError");

        mfa.crypto().MPIN.GET_G1_MULTIPLE.restore();
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

describe("Mfa Client _createSigningIdentity", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should create identity ready for signing", function (done) {
        sinon.stub(mfa, "_addShares").returns("secret");
        sinon.stub(mfa, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(mfa, "_getSignMpinId").returns("signMpinId");
        sinon.stub(mfa, "_extractPin").returns("token");

        mfa._createSigningIdentity(
            "test@example.com",
            "1234",
            {
                mpinId: "dvsMpinId",
                dtas: "dtas",
                dvsClientSecretShare: "share1Hex",
                curve: "BN254CX"
            },
            {
                dvsClientSecret: "share2Hex"
            },
            {
                privateKey: "private",
                publicKey: "public"
            }, function (err, data) {
                expect(err).to.be.null;
                expect(mfa.dvsUsers.get("test@example.com", "mpinId")).to.equal("dvsMpinId");
                expect(mfa.dvsUsers.get("test@example.com", "publicKey")).to.equal("public");
                expect(mfa.dvsUsers.get("test@example.com", "token")).to.equal("token");
                expect(mfa.dvsUsers.get("test@example.com", "state")).to.equal("REGISTERED");
                done();
            }
        );
    });

    it("should invoke callback with error if addShares fails", function (done) {
        sinon.stub(mfa, "_addShares").throws(new Error);
        sinon.stub(mfa, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(mfa, "_getSignMpinId").returns("signMpinId");
        sinon.stub(mfa, "_extractPin").returns("token");

        mfa._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if generateSignClientSecret fails", function (done) {
        sinon.stub(mfa, "_addShares").returns("secret");
        sinon.stub(mfa, "_generateSignClientSecret").throws(new Error);
        sinon.stub(mfa, "_getSignMpinId").returns("signMpinId");
        sinon.stub(mfa, "_extractPin").returns("token");

        mfa._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if getSignMpinId fails", function (done) {
        sinon.stub(mfa, "_addShares").returns("secret");
        sinon.stub(mfa, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(mfa, "_getSignMpinId").throws(new Error);
        sinon.stub(mfa, "_extractPin").returns("token");

        mfa._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if extractPin fails", function (done) {
        sinon.stub(mfa, "_addShares").returns("secret");
        sinon.stub(mfa, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(mfa, "_getSignMpinId").returns("signMpinId");
        sinon.stub(mfa, "_extractPin").throws(new Error);

        mfa._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        mfa._addShares.restore && mfa._addShares.restore();
        mfa._generateSignClientSecret.restore && mfa._generateSignClientSecret.restore();
        mfa._getSignMpinId.restore && mfa._getSignMpinId.restore();
        mfa._extractPin.restore && mfa._extractPin.restore();
    })
});

describe("Mfa Client signMessage", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return U and V", function (done) {
        sinon.stub(mfa.crypto().MPIN, "CLIENT").returns(0);
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, true);

        mfa.signMessage("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.be.null;
            expect(result.u).to.equal("");
            expect(result.v).to.equal("");
            done();
        });

        mfa._authentication.restore && mfa._authentication.restore();
    });

    it("should throw error on crypto failure", function (done) {
        sinon.stub(mfa.crypto().MPIN, "CLIENT").returns(-1);

        mfa.signMessage("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    afterEach(function () {
        mfa.crypto().MPIN.CLIENT.restore();
    });
});
