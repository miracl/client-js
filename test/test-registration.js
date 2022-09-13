import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client sendVerificationEmail", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error when verification request fails", function (done) {
        sinon.stub(client, "_request").yields({ error: true }, null);

        client.sendVerificationEmail("test@example.com", function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback when verification request succeeds", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });

        client.sendVerificationEmail("test@example.com", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client getActivationToken", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should invoke the callback data containing the activation token if request succeeds", function (done) {
        sinon.stub(client, "_request").yields(null, { actToken: "testActToken" });

        client.getActivationToken("http://example.com/verification/confirmation?code=test", function(err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            expect(data.actToken).to.equal("testActToken");
            done();
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client _registration", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(client, "_request").yields({ error: true }, null);

        client._registration("test@example.com", null, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error when registration code is not valid", function (done) {
        sinon.stub(client, "_request").yields({ status: 403 }, null);

        client._registration("test@example.com", "123456", function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("InvalidRegCodeError");
            done();
        });
    });

    it("should store started user", function(done) {
        sinon.stub(client, "_request").yields(null, { success: true, active: false });

        client._registration("test@example.com", null, function(err, data) {
            expect(client.users.exists("test@example.com")).to.be.true;
            expect(client.users.get("test@example.com", "state")).to.equal("STARTED");
            done();
        });
    });

    it("should store activated user", function(done) {
        sinon.stub(client, "_request").yields(null, { success: true, active: true });

        client._registration("test@example.com", null, function(err, data) {
            expect(client.users.exists("test@example.com")).to.be.true;
            expect(client.users.get("test@example.com", "state")).to.equal("ACTIVATED");
            done();
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client _getDeviceName", function () {
    var client;

    it("should return default device name", function () {
        client = new Client(testData.init());
        expect(client._getDeviceName()).to.equal("Browser");
    });

    it("should return provided device name", function () {
        var config = testData.init();
        config.deviceName = "test";
        client = new Client(config);
        expect(client._getDeviceName()).to.equal("test");
    })
});

describe("Client _getSecret1", function() {
    var client, spy;

    before(function () {
        client = new Client(testData.init());
        spy = sinon.spy();
    });

    it("should fire callback with error when request returns 401 & error should be NotVerifiedError", function (done) {
        sinon.stub(client, "_request").yields({ status: 401 }, null);

        client._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("NotVerifiedError");
            done();
        });
    });

    it("should fire callback with error when request returns 404 & error should be VerificationExpiredError", function (done) {
        sinon.stub(client, "_request").yields({ status: 404 }, null);

        client._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            expect(err.name).to.equal("VerificationExpiredError");
            done();
        });
    });

    it("should fire callback with error when request returns any error", function (done) {
        sinon.stub(client, "_request").yields({}, null);

        client._getSecret1("test@example.com", { regOTT: 1 }, function callback(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback when request doesn't return error", function (done) {
        sinon.stub(client, "_request").yields(null, {});

        client._getSecret1("test@example.com", { regOTT: 1 }, function callback(err, data) {
            if (err) {
                throw new Error(err);
            }
            expect(data).to.exist;
            done();
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client _getSecret2", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error, when signature2 request fails", function(done) {
        sinon.stub(client, "_request").yields({}, null);

        client._getSecret2({}, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
        client._addShares.restore && client._addShares.restore();
    });
});

describe("Client _addShares", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(client._crypto().MPIN, "RECOMBINE_G1").returns(-1);
        expect(function () {
            client._addShares("test", "test");
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(client._crypto().MPIN, "RECOMBINE_G1").returns(0);
        expect(client._addShares("test", "test")).to.equal("");
    });

    afterEach(function () {
        client._crypto().MPIN.RECOMBINE_G1.restore && client._crypto().MPIN.RECOMBINE_G1.restore();
    });
});

describe("Client _extractPin", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(client._crypto().MPIN, "EXTRACT_PIN").returns(-1);
        expect(function () {
            client._extractPin("test", "1234", "hex")
        }).to.throw("CryptoError");
    });

    it("should return combined client secret", function () {
        sinon.stub(client._crypto().MPIN, "EXTRACT_PIN").returns(0);
        expect(client._extractPin("test", "1234", "hex")).to.equal("0000");
    });

    afterEach(function () {
        client._crypto().MPIN.EXTRACT_PIN.restore && client._crypto().MPIN.EXTRACT_PIN.restore();
    });
});

describe("Client _createIdentity", function() {
    var client;

    beforeEach(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call addShares with CS share 1 and 2", function(done) {
        var addSharesStub = sinon.stub(client, "_addShares");
        var share1 = { clientSecretShare: "clientSecretValue1" };
        var share2 = { clientSecret: "clientSecretValue2" };

        client._createIdentity("test@example.com", "1234", share1, share2, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(addSharesStub.firstCall.args[0]).to.equal("clientSecretValue1");
            expect(addSharesStub.firstCall.args[1]).to.equal("clientSecretValue2");
            done();
        });
    });

    it("should call extractPin with mpinId, PIN", function (done) {
        var addSharesStub = sinon.stub(client, "_addShares");
        var extractPinStub = sinon.stub(client, "_extractPin");

        client._createIdentity("test@example.com", "1234", {}, {}, function (data) {
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
        var addSharesStub = sinon.stub(client, "_addShares").throws(thrownError);

        client._createIdentity("test@example.com", "1234", {}, {}, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    it("should call callback with error when extractPin fails", function(done) {
        var thrownError = new Error;
        var addSharesStub = sinon.stub(client, "_addShares");
        var extractPinStub = sinon.stub(client, "_extractPin").throws(thrownError);

        client._createIdentity("test@example.com", "1234", {}, {}, function(err) {
            expect(extractPinStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    afterEach(function() {
        client._extractPin.restore && client._extractPin.restore();
        client._addShares.restore && client._addShares.restore();
    });
});

describe("Client register", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should throw error w/o userId", function () {
        expect(function () {
            client.register("", null, function () {}, function () {});
        }).to.throw("Missing user ID");
    });

    it("should go through the registration flow", function (done) {
        var registrationStub = sinon.stub(client, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null);

        client.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(registrationStub.calledOnce).to.be.true;
            expect(getSecret1Stub.calledOnce).to.be.true;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(finishRegistrationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fire callback with error on error with _getSecret1", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_registration").yields(null);
        sinon.stub(client, "_getSecret1").yields({ error: true });

        client.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _getSecret2", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_registration").yields(null);
        sinon.stub(client, "_getSecret1").yields(null);
        sinon.stub(client, "_getSecret2").yields({ error: true });

        client.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _registration", function (done) {
        sinon.stub(client, "_init").yields(null, true);
        sinon.stub(client, "_registration").yields({ error: true }, null);

        client.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback, when _registration passed successful", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_registration").yields(null);
        sinon.stub(client, "_getSecret1").yields(null);
        sinon.stub(client, "_getSecret2").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, {});

        client.register("test@example.com", null, function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    // TODO: fix or test properly in _registration
    it("should fire callback with error when registration code is not valid", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_registration").yields({ error: true });

        client.register("test@example.com", "123456", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should pass provided PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.users.write("test@example.com", {pinLength: 5});

        client.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should pass default PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", null, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should auto confirm when registration code is provided", function (done) {
        var registrationStub = sinon.stub(client, "_registration").yields(null);
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", 123456, function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    afterEach(function () {
        client._registration.restore && client._registration.restore();
        client._getSecret1.restore && client._getSecret1.restore();
        client._getSecret2.restore && client._getSecret2.restore();
        client._createIdentity.restore && client._createIdentity.restore();
        client.users.remove("test@example.com");
    });
});
