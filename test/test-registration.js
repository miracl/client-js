import Mfa from "../src/mfa.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Mfa Client sendVerificationEmail", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should return error when verification request fails", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa.sendVerificationEmail("test@example.com", function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback when verification request succeeds", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa.sendVerificationEmail("test@example.com", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _registration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.clientSettings = testData.settings();
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa._registration("test@example.com", null, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error when registration code is not valid", function (done) {
        sinon.stub(mfa, "_init").yields(null, true);
        sinon.stub(mfa, "request").yields({ status: 403 }, null);

        mfa._registration("test@example.com", "123456", function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("InvalidRegCodeError");
            done();
        });
    });

    it("should store started user", function(done) {
        sinon.stub(mfa, "request").yields(null, { success: true, active: false });

        mfa._registration("test@example.com", null, function(err, data) {
            expect(mfa.users.exists("test@example.com")).to.be.true;
            expect(mfa.users.get("test@example.com", "state")).to.equal("STARTED");
            done();
        });
    });

    it("should store activated user", function(done) {
        sinon.stub(mfa, "request").yields(null, { success: true, active: true });

        mfa._registration("test@example.com", null, function(err, data) {
            expect(mfa.users.exists("test@example.com")).to.be.true;
            expect(mfa.users.get("test@example.com", "state")).to.equal("ACTIVATED");
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _getDeviceName", function () {
    var mfa;

    it("should return default device name", function () {
        mfa = new Mfa(testData.init());
        expect(mfa._getDeviceName()).to.equal("Browser");
    });

    it("should return provided device name", function () {
        var config = testData.init();
        config.deviceName = "test";
        mfa = new Mfa(config);
        expect(mfa._getDeviceName()).to.equal("test");
    })
});

describe("Mfa Client _getSecret1", function() {
    var mfa, spy;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.clientSettings = testData.settings();
        spy = sinon.spy();
    });

    it("should fire callback with error when request returns 401 & error should be NotVerifiedError", function (done) {
        sinon.stub(mfa, "request").yields({ status: 401 }, null);

        mfa._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("NotVerifiedError");
            done();
        });
    });

    it("should fire callback with error when request returns 404 & error should be VerificationExpiredError", function (done) {
        sinon.stub(mfa, "request").yields({ status: 404 }, null);

        mfa._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("VerificationExpiredError");
            done();
        });
    });

    it("should fire callback with error when request returns any error", function (done) {
        sinon.stub(mfa, "request").yields({}, null);

        mfa._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback when request doesn't return error", function (done) {
        sinon.stub(mfa, "request").yields(null, {});

        mfa._getSecret1("test@example.com", { regOTT: 1 }, function callback(err, data) {
            if (err) {
                throw new Error(err);
            }
            expect(data).to.exist;
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _getSecret2", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.clientSettings = testData.settings();
    });

    it("should return error, when signature2 request fails", function(done) {
        sinon.stub(mfa, "request").yields({}, null);

        mfa._getSecret2({}, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
        mfa._addShares.restore && mfa._addShares.restore();
    });
});

describe("Mfa Client _addShares", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.clientSettings = testData.settings();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.crypto().MPIN, "RECOMBINE_G1").returns(-1);
        expect(function () {
            mfa._addShares("test", "test");
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(mfa.crypto().MPIN, "RECOMBINE_G1").returns(0);
        expect(mfa._addShares("test", "test")).to.equal("");
    });

    afterEach(function () {
        mfa.crypto().MPIN.RECOMBINE_G1.restore && mfa.crypto().MPIN.RECOMBINE_G1.restore();
    });
});

describe("Mfa Client _extractPin", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.clientSettings = testData.settings();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.crypto().MPIN, "EXTRACT_PIN").returns(-1);
        expect(function () {
            mfa._extractPin("test", "1234", "hex")
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(mfa.crypto().MPIN, "EXTRACT_PIN").returns(0);
        expect(mfa._extractPin("test", "1234", "hex")).to.equal("0000");
    });

    afterEach(function () {
        mfa.crypto().MPIN.EXTRACT_PIN.restore && mfa.crypto().MPIN.EXTRACT_PIN.restore();
    });
});

describe("Mfa Client _createIdentity", function() {
    var mfa;

    beforeEach(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call addShares with CS share 1 and 2", function(done) {
        var addSharesStub = sinon.stub(mfa, "_addShares");
        var share1 = { clientSecretShare: "clientSecretValue1" };
        var share2 = { clientSecret: "clientSecretValue2" };

        mfa._createIdentity("test@example.com", "1234", share1, share2, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(addSharesStub.firstCall.args[0]).to.equal("clientSecretValue1");
            expect(addSharesStub.firstCall.args[1]).to.equal("clientSecretValue2");
            done();
        });
    });

    it("should call extractPin with mpinId, PIN", function (done) {
        var addSharesStub = sinon.stub(mfa, "_addShares");
        var extractPinStub = sinon.stub(mfa, "_extractPin");

        mfa._createIdentity("test@example.com", "1234", {}, {}, function (data) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(extractPinStub.calledOnce).to.be.true;
            expect(extractPinStub.firstCall.args[0]).to.equal("exampleMpinId");
            expect(extractPinStub.firstCall.args[1]).to.equal("1234");
            done();
        }, function (err) {
            throw new Error();
        });
    });

    it("should call callback with error when addShares fails", function(done) {
        var thrownError = new Error;
        var addSharesStub = sinon.stub(mfa, "_addShares").throws(thrownError);

        mfa._createIdentity("test@example.com", "1234", {}, {}, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    it("should call callback with error when extractPin fails", function(done) {
        var thrownError = new Error;
        var addSharesStub = sinon.stub(mfa, "_addShares");
        var extractPinStub = sinon.stub(mfa, "_extractPin").throws(thrownError);

        mfa._createIdentity("test@example.com", "1234", {}, {}, function(err) {
            expect(extractPinStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    afterEach(function() {
        mfa._extractPin.restore && mfa._extractPin.restore();
        mfa._addShares.restore && mfa._addShares.restore();
    });
});

describe("Mfa Client register", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should throw error w/o userId", function () {
        expect(function () {
            mfa.register("", null, function () {}, function () {});
        }).to.throw("Missing user ID");
    });

    it("should go through the registration flow", function (done) {
        var initStub = sinon.stub(mfa, "_init").yields(null);
        var registrationStub = sinon.stub(mfa, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(mfa, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(mfa, "_createIdentity").yields(null);

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(initStub.calledOnce).to.be.true;
            expect(registrationStub.calledOnce).to.be.true;
            expect(getSecret1Stub.calledOnce).to.be.true;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(finishRegistrationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fire callback with error on error with _init", function (done) {
        sinon.stub(mfa, "_init").yields({ error: true });

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _getSecret1", function (done) {
        sinon.stub(mfa, "_init").yields(null);
        sinon.stub(mfa, "_registration").yields(null);
        sinon.stub(mfa, "_getSecret1").yields({ error: true });

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _getSecret2", function (done) {
        sinon.stub(mfa, "_init").yields(null);
        sinon.stub(mfa, "_registration").yields(null);
        sinon.stub(mfa, "_getSecret1").yields(null);
        sinon.stub(mfa, "_getSecret2").yields({ error: true });

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _registration", function (done) {
        sinon.stub(mfa, "_init").yields(null, true);
        sinon.stub(mfa, "_registration").yields({ error: true }, null);

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback, when _registration passed successful", function (done) {
        sinon.stub(mfa, "_init").yields(null);
        mfa.clientSettings = testData.settings();
        sinon.stub(mfa, "_registration").yields(null);
        sinon.stub(mfa, "_getSecret1").yields(null);
        sinon.stub(mfa, "_getSecret2").yields(null);
        sinon.stub(mfa, "_createIdentity").yields(null, {});

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    // TODO: fix or test properly in _registration
    it("should fire callback with error when registration code is not valid", function (done) {
        sinon.stub(mfa, "_init").yields(null);
        sinon.stub(mfa, "_registration").yields({ error: true });

        mfa.register("test@example.com", "123456", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should pass provided PIN length to the PIN callback", function (done) {
        var initStub = sinon.stub(mfa, "_init").yields(null, true);
        var registrationStub = sinon.stub(mfa, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(mfa, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(mfa, "_createIdentity").yields(null, true);

        mfa.users.write("test@example.com", {pinLength: 5});

        mfa.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should pass default PIN length to the PIN callback", function (done) {
        var initStub = sinon.stub(mfa, "_init").yields(null, true);
        var registrationStub = sinon.stub(mfa, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(mfa, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(mfa, "_createIdentity").yields(null, true);

        mfa.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should auto confirm when registration code is provided", function (done) {
        var initStub = sinon.stub(mfa, "_init").yields(null, true);
        var registrationStub = sinon.stub(mfa, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(mfa, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(mfa, "_createIdentity").yields(null, true);

        mfa.register("test@example.com", 123456, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    afterEach(function () {
        mfa._init.restore && mfa._init.restore();
        mfa._registration.restore && mfa._registration.restore();
        mfa._getSecret1.restore && mfa._getSecret1.restore();
        mfa._getSecret2.restore && mfa._getSecret2.restore();
        mfa._createIdentity.restore && mfa._createIdentity.restore();
        mfa.users.remove("test@example.com");
    });
});
