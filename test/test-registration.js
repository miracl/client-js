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

describe("Client _createMPinID", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(client, "_request").yields({ error: true }, null);

        client._createMPinID("test@example.com", null, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error when registration code is not valid", function (done) {
        sinon.stub(client, "_request").yields({ status: 403 }, null);

        client._createMPinID("test@example.com", "123456", function callback(err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid registration code");
            done();
        });
    });

    it("should stop registration for different project", function (done) {
        sinon.stub(client, "_request").yields(null, { projectId: "anotherProjectID" });

        client._createMPinID("test@example.com", null, function(err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Registration started for different project");
            expect(client.users.exists("test@example.com")).to.be.false;
            done();
        });
    });

    it("should store started user", function(done) {
        sinon.stub(client, "_request").yields(null, { projectId: "projectID" });

        client._createMPinID("test@example.com", null, function(err, data) {
            expect(client.users.exists("test@example.com")).to.be.true;
            expect(client.users.get("test@example.com", "state")).to.equal("STARTED");
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

    it("should fire callback with error when request returns any error", function (done) {
        sinon.stub(client, "_request").yields({}, null);

        client._getSecret1({ mpinId: "0f" }, { publicKey: "public" }, function callback(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should make a proper request for client secret share", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, {});

        client._getSecret1({ mpinId: "0f", regOTT: "ott" }, { publicKey: "public" }, function callback(err, data) {
            if (err) {
                throw new Error(err);
            }

            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/signature/0f?regOTT=ott&publicKey=public");
            done();
        });
    });

    it("should fire successful callback when request doesn't return error", function (done) {
        sinon.stub(client, "_request").yields(null, {});

        client._getSecret1({ mpinId: "0f" }, { publicKey: "public" }, function callback(err, data) {
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
        client.crypto.addShares.restore && client.crypto.addShares.restore();
    });
});

describe("Client _createIdentity", function() {
    var client;

    beforeEach(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "0f",
            state: "REGISTERED"
        });
    });

    it("should call addShares with CS share 1 and 2", function(done) {
        var addSharesStub = sinon.stub(client.crypto, "addShares");
        var keypair = { privateKey: "privateKey" };
        var share1 = { dvsClientSecretShare: "clientSecretValue1" };
        var share2 = { dvsClientSecret: "clientSecretValue2" };

        client._createIdentity("test@example.com", "1234", {}, share1, share2, keypair, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(addSharesStub.firstCall.args[0]).to.equal("privateKey");
            expect(addSharesStub.firstCall.args[1]).to.equal("clientSecretValue1");
            expect(addSharesStub.firstCall.args[2]).to.equal("clientSecretValue2");
            done();
        });
    });

    it("should call extractPin with mpinId, PIN", function (done) {
        var addSharesStub = sinon.stub(client.crypto, "addShares");
        var extractPinStub = sinon.stub(client.crypto, "extractPin");

        client._createIdentity("test@example.com", "1234", { mpinId: "0f" }, {}, {}, { publicKey: "0f" }, function (data) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(extractPinStub.calledOnce).to.be.true;
            expect(extractPinStub.firstCall.args[0]).to.equal("0f");
            expect(extractPinStub.firstCall.args[1]).to.equal("0f");
            expect(extractPinStub.firstCall.args[2]).to.equal("1234");
            done();
        }, function (err) {
            throw new Error();
        });
    });

    it("should call callback with error when addShares fails", function(done) {
        var addSharesStub = sinon.stub(client.crypto, "addShares").throws(new Error("Cryptography error"));

        client._createIdentity("test@example.com", "1234", {}, {}, {}, {}, function(err) {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error");
            done();
        });
    });

    it("should call callback with error when extractPin fails", function(done) {
        var thrownError = new Error;
        var addSharesStub = sinon.stub(client.crypto, "addShares");
        var extractPinStub = sinon.stub(client.crypto, "extractPin").throws(thrownError);

        client._createIdentity("test@example.com", "1234", {}, {}, {}, {}, function(err) {
            expect(extractPinStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            done();
        });
    });

    afterEach(function() {
        client.crypto.extractPin.restore && client.crypto.extractPin.restore();
        client.crypto.addShares.restore && client.crypto.addShares.restore();
    });
});

describe("Client register", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should throw error w/o userId", function () {
        client.register("", null, function () {}, function (err, data) {
            expect(err).to.existl
            expect(err.message).to.equal("Empty user ID")
        });
    });

    it("should go through the registration flow", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null);

        client.register("test@example.com", "activationToken", function (passPin) {
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
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
        sinon.stub(client, "_getSecret1").yields({ error: true });

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _getSecret2", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
        sinon.stub(client, "_getSecret1").yields(null);
        sinon.stub(client, "_getSecret2").yields({ error: true });

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _createMPinID", function (done) {
        sinon.stub(client, "_init").yields(null, true);
        sinon.stub(client, "_createMPinID").yields({ error: true }, null);

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback, when _createMPinID passed successful", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
        sinon.stub(client, "_getSecret1").yields(null);
        sinon.stub(client, "_getSecret2").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, {});

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    // TODO: fix or test properly in _createMPinID
    it("should fire callback with error when registration code is not valid", function (done) {
        sinon.stub(client, "_init").yields(null);
        sinon.stub(client, "_createMPinID").yields({ error: true });

        client.register("test@example.com", "123456", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should pass provided PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 5 });
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", "activationToken", function (passPin, pinLength) {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should pass default PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
        var getSecret1Stub = sinon.stub(client, "_getSecret1").yields(null);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var finishRegistrationStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", "activationToken", function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should auto confirm when registration code is provided", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4 });
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
        client._createMPinID.restore && client._createMPinID.restore();
        client._getSecret1.restore && client._getSecret1.restore();
        client._getSecret2.restore && client._getSecret2.restore();
        client._createIdentity.restore && client._createIdentity.restore();
        client.users.remove("test@example.com");
    });
});
