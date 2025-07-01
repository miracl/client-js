import Client from "../src/client.js";
import sinon from "sinon";
import { expect } from "chai";

describe("Client _getPass1", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("shoud make a request for first pass", function (done) {
        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/pass1");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").throws(new Error("Cryptography error: -14"));

        client._getPass1({}, "1234", ["oidc"], [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error: -14");
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["dvs-auth"], [], [], function (err, data) {
            expect(requestStub.firstCall.args[0].data.scope).to.deep.equal(["dvs-auth"]);
            done();
        });
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client.crypto.calculatePass1.restore && client.crypto.calculatePass1.restore();
    });
});

describe("Client _getPass2", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("shoud make a request for second pass", function (done) {
        var stub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/pass2");
            expect(stub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").throws(new Error("Cryptography error"));

        client._getPass2({}, ["oidc"], "yHex", [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error");
            done();
        });
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client.crypto.calculatePass2.restore && client.crypto.calculatePass2.restore();
    });
});

describe("Client _finishAuthentication", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(client.http, "request").yields(null, { success: true });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should renew client secret if requested", function(done) {
        sinon.stub(client.http, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        var authenticationStub = sinon.stub(client, "_authentication").yields(null);
        var renewSecretStub = sinon.stub(client, "_renewSecret").yields(null);

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewSecretStub.calledOnce).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should return error when _renewSecret fails", function(done) {
        sinon.stub(client.http, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        var renewSecretStub = sinon.stub(client, "_renewSecret").yields(new Error("Renew secret error"));

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Renew secret error");
            done();
        });
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client._renewSecret.restore && client._renewSecret.restore();
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client _renewSecret", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should renew the identity secret", function (done) {
        var createMPinIDStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret").yields(null, true);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.be.null;
            expect(createMPinIDStub.calledOnce).to.be.true;
            expect(getSecretStub.calledTwice).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call error callback on _createMPinID failure", function (done) {
        sinon.stub(client, "_createMPinID").yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            done();
        });
    });

    it("should call error callback on first _getSecret failure", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            done();
        });
    });

    it("should call error callback on second _getSecret failure", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        var getSecretStub = sinon.stub(client, "_getSecret");
        getSecretStub.onFirstCall().yields(null);
        getSecretStub.onSecondCall().yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            done();
        });
    });

    it("should call error callback on createIdentity error", function (done) {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null, true);
        sinon.stub(client, "_createIdentity").yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            done();
        });
    });

    afterEach(function () {
        client._createMPinID.restore && client._createMPinID.restore();
        client._getSecret.restore && client._getSecret.restore();
        client._createIdentity.restore && client._createIdentity.restore();
    })
});

describe("Client _authentication", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should fail w/o userId", function (done) {
        client._authentication("", "", ["jwt"], function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            done();
        });
    });

    it("should fail when user does not exist", function (done) {
        client._authentication("missing@example.com", "", ["jwt"], function (err) {
            expect(err).to.exist;
            expect(err.message).to.equal("User not found");
            done();
        });
    });

    it("should go through the authentication flow", function (done) {
        var getPass1Stub = sinon.stub(client, "_getPass1").yields(null, {});
        var getPass2Stub = sinon.stub(client, "_getPass2").yields(null, {});
        var finishAuthenticationStub = sinon.stub(client, "_finishAuthentication").yields(null, true);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.be.null;
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when MPIN ID has expired", function (done) {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), { error: "EXPIRED_MPINID" });

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Revoked");
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        client._authentication("test@example.com", "1234", ["jwt"], function (err, data) {
            expect(err).to.be.null;
            expect(requestStub.callCount).to.equal(1);
            expect(data).to.exist;
            done();
        });
    });

    it("should call the error callback on authenticate error", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { status: 400 });

        client._authentication("test@example.com", "1234", ["jwt"], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Authentication fail");
            done();
        });
    });

    it("should call the error callback on unsuccessful authentication", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { error: "UNSUCCESSFUL_AUTHENTICATION" });

        client._authentication("test@example.com", "1234", ["jwt"], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Unsuccessful authentication");
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error REVOKED_MPINID", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        var requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { status: 410, error: "REVOKED_MPINID" });

        var userWriteSpy = sinon.spy(client.users, "write");

        client._authentication("test@example.com", "1234", ["jwt"], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Revoked");
            expect(userWriteSpy.calledOnce).to.be.true;
            expect(userWriteSpy.firstCall.args[0]).to.equal("test@example.com");
            expect(userWriteSpy.firstCall.args[1].state).to.equal("REVOKED");
            done();
        });
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client._getPass1.restore && client._getPass1.restore();
        client._getPass2.restore && client._getPass2.restore();
        client._finishAuthentication.restore && client._finishAuthentication.restore();
    });
});

describe("Client authenticate", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'jwt'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticate("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["jwt"]);
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithQRCode", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithQRCode("test@example.com", "https://example.com/mobile/auth#accessID", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithAppLink", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithAppLink("test@example.com", "https://example.com/mobile/auth#accessID", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithNotificationPayload", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithNotificationPayload({userID: "test@example.com", qrURL: "https://example.com/mobile/auth#accessID"}, "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    it("should fail w/o user ID", function (done) {
        client.authenticateWithNotificationPayload({qrURL: "https://example.com/mobile/auth#accessID"}, "1234", function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid push notification payload");
            done();
        });
    });

    it("should fail w/o QR URL", function (done) {
        client.authenticateWithNotificationPayload({userID: "test@example.com"}, "1234", function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid push notification payload");
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client generateQuickCode", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'reg-code'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, {});
        var requestStub = sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });

        client.generateQuickCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["reg-code"]);
            expect(data.code).to.equal("123456");
            expect(data.OTP).to.equal("123456");
            expect(data.ttlSeconds).to.equal(60);
            expect(data.expireTime).to.equal(1737520575);
            done();
        });
    });

    it("should fail on _authentication error", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(new Error("Authentication fail"), null);

        client.generateQuickCode("test@example.com", "1234", function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Authentication fail");
            done();
        });
    });

    it("should fail on verification/quickcode request error", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, {});
        var requestStub = sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.generateQuickCode("test@example.com", "1234", function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
        client.http.request.restore && client.http.request.restore();
    });
});
