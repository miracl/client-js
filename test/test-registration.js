import Client from "../src/client.js";
import sinon from "sinon";
import { expect } from "chai";

describe("Client sendVerificationEmail", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should fail w/o userId", function (done) {
        client.sendVerificationEmail("", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            done();
        });
    });

    it("should return error when verification request fails", function (done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.sendVerificationEmail("test@example.com", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Verification fail");
            done();
        });
    });

    it("should return error when verification request fails with backoff error", function (done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { error: "REQUEST_BACKOFF" });

        client.sendVerificationEmail("test@example.com", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request backoff");
            done();
        });
    });

    it("should call success callback when verification request succeeds", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });

        client.sendVerificationEmail("test@example.com", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client getActivationToken", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should fail w/o userId", function (done) {
        client.getActivationToken("http://example.com/verification/confirmation?code=test", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            done();
        });
    });

    it("should fail w/o code", function (done) {
        client.getActivationToken("http://example.com/verification/confirmation?user_id=test@example.com", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty verification code");
            done();
        });
    });

    it("should fail when the request fails", function (done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", function(err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Get activation token fail");
            done();
        });
    });

    it("should fail when the verification fails", function (done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { error: "UNSUCCESSFUL_VERIFICATION" });

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", function(err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Unsuccessful verification");
            done();
        });
    });

    it("should invoke the callback data containing the activation token if request succeeds", function (done) {
        sinon.stub(client.http, "request").yields(null, { actToken: "testActToken" });

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", function(err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            expect(data.actToken).to.equal("testActToken");
            done();
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client _createMPinID", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client._createMPinID("test@example.com", null, { publicKey: "00" }, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should store started user", function(done) {
        sinon.stub(client.http, "request").yields(null, { projectId: "projectID" });

        client._createMPinID("test@example.com", null, { publicKey: "00" }, function(err, data) {
            expect(client.users.exists("test@example.com")).to.be.true;
            expect(client.users.get("test@example.com", "state")).to.equal("STARTED");
            done();
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
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

describe("Client _getSecret", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return error, when signature request fails", function(done) {
        sinon.stub(client.http, "request").yields(new Error("Request failed"), null);

        client._getSecret("secretUrl", function(err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request failed");
            done();
        });
    });

    it("should retry if the request was aborted", function(done) {
        var requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(null, {});

        client._getSecret("secretUrl", function(err) {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.be.null;
            done();
        });
    });

    it("should return error if the retried request fails", function(done) {
        var requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(new Error("Request failed"), null);

        client._getSecret("secretUrl", function(err) {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("Request failed");
            done();
        });
    });

    it("should return error if the retried request is aborted", function(done) {
        var requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(new Error("The request was aborted"), null);

        client._getSecret("secretUrl", function(err) {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("The request was aborted");
            done();
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
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
        var share1 = { dvsClientSecret: "clientSecretValue1" };
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

    it("should return error w/o userId", function () {
        client.register("", null, function () {}, function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
        });
    });

    it("should return error w/o activation token", function () {
        client.register("test@example.com", null, function () {}, function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty activation token");
        });
    });

    it("should go through the registration flow", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret").yields(null);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null);

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(registrationStub.calledOnce).to.be.true;
            expect(getSecretStub.calledTwice).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fire callback with error on error with first _getSecret", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(new Error("Request error"));

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with second _getSecret", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret");
        getSecretStub.onFirstCall().yields(null);
        getSecretStub.onSecondCall().yields(new Error("Request error"));

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire callback with error on error with _createMPinID", function (done) {
        sinon.stub(client, "_createMPinID").yields(new Error("Request error"), null);

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successful callback, when _createMPinID passed successful", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, {});

        client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should fire callback with error when registration code is not valid", function (done) {
        sinon.stub(client, "_createMPinID").yields(new Error("Request failed"), { status: 403, error: "INVALID_ACTIVATION_TOKEN" });

        client.register("test@example.com", "123456", function (passPin) {
            passPin("1234");
        }, function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid activation token");
            done();
        });
    });

    it("should stop registration for different project", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { projectId: "anotherProjectID" });

        client.register("test@example.com", "123456", function (passPin) {
            passPin("1234");
        }, function(err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Project mismatch");
            expect(client.users.exists("test@example.com")).to.be.false;
            done();
        });
    });

    it("should pass provided PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 5, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret").yields(null);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", "activationToken", function (passPin, pinLength) {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    it("should pass default PIN length to the PIN callback", function (done) {
        var registrationStub = sinon.stub(client, "_createMPinID").yields(null, { projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret").yields(null);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client.register("test@example.com", "activationToken", function (passPin, pinLength) {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, function (err, data) {
            expect(err).to.be.null;
            done();
        });
    });

    afterEach(function () {
        client._createMPinID.restore && client._createMPinID.restore();
        client._getSecret.restore && client._getSecret.restore();
        client._createIdentity.restore && client._createIdentity.restore();
        client.users.remove("test@example.com");
    });
});
