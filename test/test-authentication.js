import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client _getPass1", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.clientSettings = testData.settings();
    });

    it("shoud make a request for first pass", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_1").returns(0);

        client._getPass1("test@example.com", "1234", ["oidc"], [], [], function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0]).to.be.an.object;
            expect(requestStub.firstCall.args[0].url).to.equal("https://api.miracl.net/rps/pass1");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_1").returns(0);

        client._getPass1("test@example.com", "1234", ["oidc"], [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_1").returns(-14);

        client._getPass1("test@example.com", "1234", ["oidc"], [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_1").returns(0);

        client._getPass1("test@example.com", "1234", ["dvs-auth"], [], [], function (err, data) {
            expect(requestStub.firstCall.args[0].data.scope).to.deep.equal(["dvs-auth"]);
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
        client.crypto().MPIN.CLIENT_1.restore && client.crypto().MPIN.CLIENT_1.restore();
    });
});

describe("Client _getPass2", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.clientSettings = testData.settings();
    });

    it("shoud make a request for second pass", function (done) {
        var stub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_2").returns(0);

        client._getPass2("test@example.com", ["oidc"], "yHex", [], [], function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.firstCall.args[0]).to.be.an.object;
            expect(stub.firstCall.args[0].url).to.equal("https://api.miracl.net/rps/pass2");
            expect(stub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_2").returns(0);

        client._getPass2("test@example.com", ["oidc"], "yHex", [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_2").returns(-14);

        client._getPass2("test@example.com", ["oidc"], "yHex", [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    it("should make a request for OTP", function (done) {
        var stub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_2").returns(0);

        client._getPass2("test@example.com", ["otp"], "yHex", [], [], function (err, data) {
            expect(stub.calledOnce).to.be.true;
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client.crypto().MPIN, "CLIENT_2").returns(0);

        client.dvsUsers.write("test@example.com", {
            mpinId: "thisIsDvsId",
            state: "ACTIVATED"
        });

        client._getPass2("test@example.com", ["dvs-auth"], "yHex", [], [], function (err, data) {
            expect(requestStub.firstCall.args[0].data.mpin_id).to.equal("thisIsDvsId");
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
        client.crypto().MPIN.CLIENT_2.restore && client.crypto().MPIN.CLIENT_2.restore();
    });
});

describe("Client _finishAuthentication", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.clientSettings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(client, "request").yields({ error: true }, null);

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should mark an identity as revoked", function (done) {
        sinon.stub(client, "request").yields({ status: 410 }, null);

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            expect(client.users.get("test@example.com", "state")).to.equal(client.users.states.revoked);
            done();
        });
    });

    it("should renew identity secret if requested", function(done) {
        sinon.stub(client, "request").yields(null, { success: true, renewSecret: { test: 1 } });
        var renewSecretStub = sinon.stub(client, "_renewSecret").yields(null);

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should renew DVS secret if requested", function(done) {
        sinon.stub(client, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        var renewDvsSecretStub = sinon.stub(client, "_renewDvsSecret").yields(null);

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewDvsSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
    });
});

describe("Client _renewSecret", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.clientSettings = testData.settings();
    });

    it("should renew the identity secret", function (done) {
        sinon.stub(client, "request").yields(null, {});
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null);
        var authenticateStub = sinon.stub(client, "authenticate").yields(null);

        client._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.be.null;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            expect(authenticateStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call error callback on getSecret2 error", function (done) {
        sinon.stub(client, "_getSecret2").yields({ error: true });

        client._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call error callback on createIdentity error", function (done) {
        sinon.stub(client, "_getSecret2").yields(null);
        sinon.stub(client, "_createIdentity").yields({ error: true });

        client._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call error callback on authenticate error", function (done) {
        sinon.stub(client, "_getSecret2").yields(null);
        sinon.stub(client, "_createIdentity").yields(null);
        sinon.stub(client, "authenticate").yields({ error: true });

        client._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
        client._getSecret2.restore && client._getSecret2.restore();
        client._createIdentity.restore && client._createIdentity.restore();
        client.authenticate.restore && client.authenticate.restore();
    });
});

describe("Client _authentication", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should fail w/o userId", function (done) {
        client._authentication("", "", ["otp"], function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
            done();
        });
    });

    it("should go through the authentication flow", function (done) {
        var initStub = sinon.stub(client, "_init").yields(null, true);
        var getPass1Stub = sinon.stub(client, "_getPass1").yields(null, {});
        var getPass2Stub = sinon.stub(client, "_getPass2").yields(null, {});
        var finishAuthenticationStub = sinon.stub(client, "_finishAuthentication").yields(null, true);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.be.null;
            expect(initStub.calledOnce).to.be.true;
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(client, "_init").yields(null, true);
        sinon.stub(client, "_getPass1").yields({ error: true }, null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(client, "_init").yields(null, true);
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields({ error: true }, null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        client._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.be.null;
            // Called twice for init and authenticate
            expect(requestStub.callCount).to.equal(2);
            expect(data).to.exist;
            done();
        });
    });

    it("should call the error callback on authenticate error", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 400 }, null);

        client._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error 410", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 410 }, null);

        var userWriteSpy = sinon.spy(client.users, "write");

        client._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.exist;
            expect(userWriteSpy.calledOnce).to.be.true;
            expect(userWriteSpy.firstCall.args[0]).to.equal("test@example.com");
            expect(userWriteSpy.firstCall.args[1].state).to.equal("REVOKED");
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
        client._init.restore && client._init.restore();
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
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticate("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Client generateOTP", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'otp'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.generateOTP("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["otp"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Client generateQuickCode", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'reg-code'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.generateQuickCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["reg-code"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Client generateAuthCode", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'authcode'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.generateAuthCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["authcode"]);
            done();
        });

        authenticationStub.restore();
    });
});
