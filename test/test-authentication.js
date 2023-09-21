import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client _getPass1", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("shoud make a request for first pass", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0]).to.be.an.object;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/pass1");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").throws(new Error("Cryptography error: -14"));

        client._getPass1({}, "1234", ["oidc"], [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error: -14");
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["dvs-auth"], [], [], function (err, data) {
            expect(requestStub.firstCall.args[0].data.scope).to.deep.equal(["dvs-auth"]);
            done();
        });
    });

    afterEach(function () {
        client._request.restore && client._request.restore();
        client.crypto.calculatePass1.restore && client.crypto.calculatePass1.restore();
    });
});

describe("Client _getPass2", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("shoud make a request for second pass", function (done) {
        var stub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.firstCall.args[0]).to.be.an.object;
            expect(stub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/pass2");
            expect(stub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").throws(new Error("Cryptography error"));

        client._getPass2({}, ["oidc"], "yHex", [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error");
            done();
        });
    });

    it("should make a request for OTP", function (done) {
        var stub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["otp"], "yHex", [], [], function (err, data) {
            expect(stub.calledOnce).to.be.true;
            done();
        });
    });

    afterEach(function () {
        client._request.restore && client._request.restore();
        client.crypto.calculatePass2.restore && client.crypto.calculatePass2.restore();
    });
});

describe("Client _finishAuthentication", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(client, "_request").yields({ error: true }, null);

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should mark an identity as revoked", function (done) {
        sinon.stub(client, "_request").yields({ status: 410 }, null);

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            expect(client.users.get("test@example.com", "state")).to.equal(client.users.states.revoked);
            done();
        });
    });

    it("should renew client secret if requested", function(done) {
        sinon.stub(client, "_request").yields(null, { success: true, dvsRegister: { test: 1 } });
        var authenticationStub = sinon.stub(client, "_authentication").yields(null);
        var renewSecretStub = sinon.stub(client, "_renewSecret").yields(null);

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewSecretStub.calledOnce).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    afterEach(function () {
        client._request.restore && client._request.restore();
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client _renewSecret", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should renew the identity secret", function (done) {
        var getWaMSecret1Stub = sinon.stub(client, "_getWaMSecret1").yields(null, true);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null, true);
        var createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, true);

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.be.null;
            expect(getWaMSecret1Stub.calledOnce).to.be.true;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call error callback on _getWaMSecret1 failure", function (done) {
        sinon.stub(client, "_getWaMSecret1").yields({ error: true });

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should call error callback on _getSecret2 failure", function (done) {
        sinon.stub(client, "_getWaMSecret1").yields(null, true);
        sinon.stub(client, "_getSecret2").yields({ error: true }, null);

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should call error callback on createIdentity error", function (done) {
        sinon.stub(client, "_getWaMSecret1").yields(null, true);
        sinon.stub(client, "_getSecret2").yields(null, true);
        sinon.stub(client, "_createIdentity").yields({ error: true });

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    afterEach(function () {
        client._getWaMSecret1.restore && client._getWaMSecret1.restore();
        client._getSecret2.restore && client._getSecret2.restore();
        client._createIdentity.restore && client._createIdentity.restore();
    })
});

describe("Client _getWaMSecret1", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(client, "_request").yields({}, null);

        client._getWaMSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback with data", function (done) {
        sinon.stub(client, "_request").yields(null, { success: true });

        client._getWaMSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, cs1Data) {
            expect(err).to.be.null;
            expect(cs1Data).to.exist;
            expect(cs1Data).to.have.property("success");
            expect(cs1Data.success).to.be.true;
            done();
        });
    });

    it("should make request to dvs register endpoint", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });

        client._getWaMSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/rps/v2/dvsregister");
            done();
        });
    });

    it("should make request with public key", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client, "_getDeviceName").returns("device");

        client._getWaMSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].data).to.deep.equal({ publicKey: "public", dvsRegisterToken: "dvsRegisterToken" });
            done();
        });
    });

    afterEach(function () {
        client._request.restore && client._request.restore();
    });
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
        client._authentication("", "", ["otp"], function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
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
        sinon.stub(client, "_getPass1").yields({ error: true }, null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields({ error: true }, null);

        client._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        client._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.be.null;
            expect(requestStub.callCount).to.equal(1);
            expect(data).to.exist;
            done();
        });
    });

    it("should call the error callback on authenticate error", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        requestStub.onFirstCall().yields({ error: true, status: 400 }, null);

        client._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error 410", function (done) {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        var requestStub = sinon.stub(client, "_request").yields(null, { success: true });
        requestStub.onFirstCall().yields({ error: true, status: 410 }, null);

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
        client._request.restore && client._request.restore();
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

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticate("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client generateOTP", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
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
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.generateQuickCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["reg-code"]);
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client generateAuthCode", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'authcode'", function (done) {
        var fetchAccessIdStub = sinon.stub(client, "fetchAccessId").yields(null, { success: true });
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.generateAuthCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(fetchAccessIdStub.calledOnce).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["authcode"]);
            done();
        });
    });

    afterEach(function () {
        client.fetchAccessId.restore && client.fetchAccessId.restore();
        client._authentication.restore && client._authentication.restore();
    });
});
