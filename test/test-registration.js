if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client startRegistration", function() {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(testData.init());
    });

    it("should throw error w/o userId", function () {
        expect(function () {
            mfa.startRegistration("", null, function () {}, function () {});
        }).to.throw("Missing user ID");
    });

    it("should fire errorCb, when have problem with _registration", function (done) {
        sinon.stub(mfa, "_registration").yields({}, null);
        mfa.startRegistration("test@example.com", null, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb, when _registration passed successful", function (done) {
        sinon.stub(mfa, "_registration").yields(null, {});

        mfa.startRegistration("test@example.com", null, function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) {
            throw new Error(err.name);
        });
    });

    it("should fire errorCb when registration code is not valid", function (done) {
        sinon.stub(mfa, "_registration").yields({ status: 403 }, null);

        mfa.startRegistration("test@example.com", "123456", function successCb(data) {
            throw new Error();
        }, function errorCb(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("InvalidRegCodeError");
            done();
        });
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
    });
});

describe("Mfa Client _registration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa._registration("test@example.com", null, function(err) {
            expect(err).to.exist;
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
        mfa = new Mfa({
            server: testData.init().server,
            customerId: testData.init().customerId,
            seed: testData.init().seed
        });
        expect(mfa._getDeviceName()).to.equal("Browser");
    });

    it("should return provided device name", function () {
        mfa = new Mfa({
            server: testData.init().server,
            customerId: testData.init().customerId,
            seed: testData.init().seed,
            deviceName: "test"
        });
        expect(mfa._getDeviceName()).to.equal("test");
    })
});

describe("Mfa Client confirmRegistration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should throw error w/o userId", function () {
        expect(function () {
            mfa.confirmRegistration("", function () {}, function () {});
        }).to.throw("Missing user ID");
    });

    it("should fire errorCb when _getSecret1 return 401 & error should be NotVerifiedError", function (done) {
        sinon.stub(mfa, "_getSecret1").yields({ status: 401 }, null);
        mfa.users.write("test@example.com", { state: "ACTIVATED" });

        mfa.confirmRegistration("test@example.com", function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("NotVerifiedError");
            done();
        });
    });

    it("should fire errorCb when _getSecret1 return 404 & error should be VerificationExpiredError", function (done) {
        sinon.stub(mfa, "_getSecret1").yields({ status: 404 }, null);
        mfa.users.write("test@example.com", { state: "ACTIVATED" });

        mfa.confirmRegistration("test@example.com", function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("VerificationExpiredError");
            done();
        });
    });

    it("should fire errorCb when _getSecret1 returns another error", function (done) {
        sinon.stub(mfa, "_getSecret1").yields({ status: 400 }, null);
        mfa.users.write("test@example.com", { state: "ACTIVATED" });

        mfa.confirmRegistration("test@example.com", function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire errorCb when _getSecret1 return other error", function (done) {
        sinon.stub(mfa, "_getSecret1").yields({}, null);

        mfa.confirmRegistration("test@example.com", function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb when _getSecret1 return Ok", function (done) {
        sinon.stub(mfa, "_getSecret").yields(null, {});
        mfa.users.write("test@example.com", { state: "ACTIVATED" });

        mfa.confirmRegistration("test@example.com", function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) {
            throw Error(err);
        });

    });

    it("should fire errorCb when identity is not in suitable state", function (done) {
        sinon.stub(mfa, "_getSecret").yields(null, {});
        mfa.users.write("test@example.com", { state: "INVALID" });

        mfa.confirmRegistration("test@example.com", function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return MISSING_USERID when try to call confirmRegistration w/o userId", function () {
        it("should throw error w/o userId", function () {
            expect(function () {
                mfa.confirmRegistration("", function () {}, function () {});
            }).to.throw("Missing user ID");
        });
    });

    afterEach(function() {
        mfa._getSecret.restore && mfa._getSecret.restore();
        mfa._getSecret1.restore && mfa._getSecret1.restore();
    });
});

describe("Mfa Client _getSecret", function() {
    var mfa, spy;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
        spy = sinon.spy();
    });

    it("should return error, when signature request fail", function(done) {
        sinon.stub(mfa, "request").yields({}, null);

        mfa._getSecret("test@example.com", function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error, when signature2 request fail", function(done) {
        var stub = sinon.stub(mfa, "request");
        stub.onCall(0).yields(null, {});
        stub.onCall(1).yields({}, null);

        mfa._getSecret("test@example.com", function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call addShares with CS and CSShare", function(done) {
        var addSharesStub = sinon.stub(mfa, "_addShares");
        var stub = sinon.stub(mfa, "request");
        stub.onCall(0).yields(null, { clientSecretShare: "clientSecretValue1" });
        stub.onCall(1).yields(null, { clientSecret: "clientSecretValue2" });

        mfa._getSecret("test@example.com", function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(addSharesStub.getCalls()[0].args[0]).to.equal("clientSecretValue1");
            expect(addSharesStub.getCalls()[0].args[1]).to.equal("clientSecretValue2");
            done();
        });
    });

    it("should return error when addShares fails", function(done) {
        var thrownError = new Error;
        var addSharesStub = sinon.stub(mfa, "_addShares").throws(thrownError);
        var stub = sinon.stub(mfa, "request");
        stub.onCall(0).yields(null, { clientSecretShare: "clientSecretValue1" });
        stub.onCall(1).yields(null, { clientSecret: "clientSecretValue2" });

        mfa._getSecret("test@example.com", function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(err).to.equal(thrownError);
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
        mfa.options.settings = testData.settings();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "RECOMBINE_G1").returns(-1);
        expect(function () {
            mfa._addShares("test", "test");
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(mfa.mpin, "RECOMBINE_G1").returns(0);
        expect(mfa._addShares("test", "test")).to.equal("");
    });

    afterEach(function () {
        mfa.mpin.RECOMBINE_G1.restore && mfa.mpin.RECOMBINE_G1.restore();
    });
});

describe("Mfa Client _calculateMPinToken", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(mfa.mpin, "EXTRACT_PIN").returns(-1);
        expect(function () {
            mfa._calculateMPinToken("test", "1234", "hex")
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(mfa.mpin, "EXTRACT_PIN").returns(0);
        expect(mfa._calculateMPinToken("test", "1234", "hex")).to.equal("0000");
    });

    afterEach(function () {
        mfa.mpin.EXTRACT_PIN.restore && mfa.mpin.EXTRACT_PIN.restore();
    });
});

describe("Mfa Client finishRegistration", function() {
    var mfa;

    beforeEach(function () {
        localStorage.clear();
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should throw error w/o userId", function () {
        expect(function () {
            mfa.finishRegistration("", "", function () {}, function () {});
        }).to.throw("Missing user ID");
    });

    it("should call errorCb with IdentityError when user is not suitable", function (done) {
        mfa.users.write("test@example.com", { state: "STARTED" });

        mfa.finishRegistration("test@example.com", "1234", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
            done();
        });
    });

    it("should call calculateMpinToken with mpinId, Pin", function (done) {
        var calculateMPinTokenStub = sinon.stub(mfa, "_calculateMPinToken");

        mfa.finishRegistration("test@example.com", "1234", function (data) {
            expect(calculateMPinTokenStub.calledOnce).to.be.true;
            expect(calculateMPinTokenStub.getCalls()[0].args[0]).to.equal("exampleMpinId");
            expect(calculateMPinTokenStub.getCalls()[0].args[1]).to.equal("1234");
            done();
        });
    });

    it("should call errorCb when calculateMpinToken fails", function(done) {
        var thrownError = new Error;
        var calculateMPinTokenStub = sinon.stub(mfa, "_calculateMPinToken").throws(thrownError);

        mfa.finishRegistration("test@example.com", "1234", function () {}, function(err) {
            expect(calculateMPinTokenStub.calledOnce).to.be.true;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
        mfa._calculateMPinToken.restore && mfa._calculateMPinToken.restore();
    });
});

describe("Mfa Client register", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should go through the registration flow", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startRegistrationStub = sinon.stub(mfa, "startRegistration").yields(true);
        var confirmRegistrationStub = sinon.stub(mfa, "confirmRegistration").yields(true);
        var finishRegistrationStub = sinon.stub(mfa, "finishRegistration").yields(true);

        mfa.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (confirm) {
            confirm();
        }, function (data) {
            expect(initStub.calledOnce).to.be.true;
            expect(startRegistrationStub.calledOnce).to.be.true;
            expect(confirmRegistrationStub.calledOnce).to.be.true;
            expect(finishRegistrationStub.calledOnce).to.be.true;
            done();
        }, function (err) {
            throw Error(err);
        });
    });

    it("should pass provided PIN length to the PIN callback", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startRegistrationStub = sinon.stub(mfa, "startRegistration").yields(true);
        var confirmRegistrationStub = sinon.stub(mfa, "confirmRegistration").yields(true);
        var finishRegistrationStub = sinon.stub(mfa, "finishRegistration").yields(true);

        mfa.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, function (confirm) {
            mfa.users.write("test@example.com", {pinLength: 5});
            confirm();
        }, function (data) {
            done();
        }, function (err) {
            throw Error(err);
        });
    });

    it("should pass default PIN length to the PIN callback", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startRegistrationStub = sinon.stub(mfa, "startRegistration").yields(true);
        var confirmRegistrationStub = sinon.stub(mfa, "confirmRegistration").yields(true);
        var finishRegistrationStub = sinon.stub(mfa, "finishRegistration").yields(true);

        mfa.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (confirm) {
            confirm();
        }, function (data) {
            done();
        }, function (err) {
            throw Error(err);
        });
    });

    it("should auto confirm when registration code is provided", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startRegistrationStub = sinon.stub(mfa, "startRegistration").yields(true);
        var confirmRegistrationStub = sinon.stub(mfa, "confirmRegistration").yields(true);
        var finishRegistrationStub = sinon.stub(mfa, "finishRegistration").yields(true);

        mfa.register("test@example.com", 123456, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function () {
            throw Error("Called confirm");
        }, function (data) {
            done();
        }, function (err) {
            throw Error(err);
        });
    });

    afterEach(function () {
        mfa.init.restore && mfa.init.restore();
        mfa.startRegistration.restore && mfa.startRegistration.restore();
        mfa.confirmRegistration.restore && mfa.confirmRegistration.restore();
        mfa.finishRegistration.restore && mfa.finishRegistration.restore();
        mfa.users.delete("test@example.com");
    });
});
