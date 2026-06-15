import { afterEach, before, describe, it } from "mocha";
import Client from "../src/client.js";
import { expect } from "chai";
import sinon from "sinon";
import testConfig from "./config.js";

describe("Client _getPass1", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("shoud make a request for first pass", (done) => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], () => {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/pass1");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["oidc"], [], [], (err, data) => {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").throws(new Error("Cryptography error: -14"));

        client._getPass1({}, "1234", ["oidc"], [], [], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error: -14");
            expect(data).to.be.null;
            done();
        });
    });

    it("should handle dvs scope", (done) => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass1").returns({U: "", UT: ""});

        client._getPass1({}, "1234", ["dvs-auth"], [], [], (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ success: true });
            expect(requestStub.firstCall.args[0].data.scope).to.deep.equal(["dvs-auth"]);
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client.crypto.calculatePass1.restore && client.crypto.calculatePass1.restore();
    });
});

describe("Client _getPass2", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("shoud make a request for second pass", (done) => {
        const stub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], () => {
            expect(stub.calledOnce).to.be.true;
            expect(stub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/pass2");
            expect(stub.firstCall.args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").returns();

        client._getPass2({}, ["oidc"], "yHex", [], [], (err, data) => {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client.crypto, "calculatePass2").throws(new Error("Cryptography error"));

        client._getPass2({}, ["oidc"], "yHex", [], [], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client.crypto.calculatePass2.restore && client.crypto.calculatePass2.restore();
    });
});

describe("Client _finishAuthentication", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should call error callback when request fails", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", (err, data) => {
            expect(err).to.exist;
            expect(data).to.deep.equal({ status: 400 });
            done();
        });
    });

    it("should call the success callback after successful request", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });

        client._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should renew client secret if requested", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { auth: true });
        const renewSecretStub = sinon.stub(client, "_renewSecret").yields(null);

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ auth: true });
            expect(renewSecretStub.calledOnce).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should return error when _renewSecret fails", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        sinon.stub(client, "_renewSecret").yields(new Error("Renew secret error"));

        client._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Renew secret error");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client._renewSecret.restore && client._renewSecret.restore();
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client _renewSecret", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should renew the identity secret", (done) => {
        const createMPinIDStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        const getSecretStub = sinon.stub(client, "_getSecret").yields(null, { secret: true });
        const createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, { createIdentity: true });

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ createIdentity: true });
            expect(createMPinIDStub.calledOnce).to.be.true;
            expect(getSecretStub.calledTwice).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call error callback on _createMPinID failure", (done) => {
        sinon.stub(client, "_createMPinID").yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call error callback on first _getSecret failure", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call error callback on second _getSecret failure", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        const getSecretStub = sinon.stub(client, "_getSecret");
        getSecretStub.onFirstCall().yields(null);
        getSecretStub.onSecondCall().yields(new Error("Request error"));

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call error callback on createIdentity error", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null, true);
        sinon.stub(client, "_createIdentity").yields(new Error("Request error"), null);

        client._renewSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client._createMPinID.restore && client._createMPinID.restore();
        client._getSecret.restore && client._getSecret.restore();
        client._createIdentity.restore && client._createIdentity.restore();
    });
});

describe("Client _authentication", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should fail w/o userId", (done) => {
        client._authentication("", "", ["jwt"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail when user does not exist", (done) => {
        client._authentication("missing@example.com", "", ["jwt"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("User not found");
            expect(data).to.be.null;
            done();
        });
    });

    it("should go through the authentication flow", (done) => {
        const getPass1Stub = sinon.stub(client, "_getPass1").yields(null, {});
        const getPass2Stub = sinon.stub(client, "_getPass2").yields(null, {});
        const finishAuthenticationStub = sinon.stub(client, "_finishAuthentication").yields(null, { success: true });

        client._authentication("test@example.com", "1234", ["oidc"], (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ success: true });
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", (done) => {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ["oidc"], (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should call callback with error when MPIN ID has expired", (done) => {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), { error: "EXPIRED_MPINID" });

        client._authentication("test@example.com", "1234", ["oidc"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Revoked");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", (done) => {
        sinon.stub(client, "_getPass1").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ["oidc"], (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", (done) => {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(new Error("Request error"), null);

        client._authentication("test@example.com", "1234", ["oidc"], (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should call the success callback after getting the passes", (done) => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        client._authentication("test@example.com", "1234", ["jwt"], (err, data) => {
            expect(err).to.be.null;
            expect(requestStub.callCount).to.equal(1);
            expect(data).to.exist;
            done();
        });
    });

    it("should call the error callback on authenticate error", (done) => {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { status: 400 });

        client._authentication("test@example.com", "1234", ["jwt"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Authentication fail");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call the error callback on unsuccessful authentication", (done) => {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { error: "UNSUCCESSFUL_AUTHENTICATION" });

        client._authentication("test@example.com", "1234", ["jwt"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Unsuccessful authentication");
            expect(data).to.be.null;
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error REVOKED_MPINID", (done) => {
        sinon.stub(client, "_getPass1").yields(null, { success: true });
        sinon.stub(client, "_getPass2").yields(null, { success: true });

        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(new Error("Request error"), { status: 410, error: "REVOKED_MPINID" });

        const userWriteSpy = sinon.spy(client.users, "write");

        client._authentication("test@example.com", "1234", ["jwt"], (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Revoked");
            expect(data).to.be.null;
            expect(userWriteSpy.calledOnce).to.be.true;
            expect(userWriteSpy.firstCall.args[0]).to.equal("test@example.com");
            expect(userWriteSpy.firstCall.args[1].state).to.equal("REVOKED");
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client._getPass1.restore && client._getPass1.restore();
        client._getPass2.restore && client._getPass2.restore();
        client._finishAuthentication.restore && client._finishAuthentication.restore();
    });
});

describe("Client authenticate", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'jwt'", (done) => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticate("test@example.com", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["jwt"]);
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithQRCode", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", (done) => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithQRCode("test@example.com", "https://example.com/mobile/auth#accessID", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithAppLink", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", (done) => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithAppLink("test@example.com", "https://example.com/mobile/auth#accessID", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client authenticateWithNotificationPayload", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'oidc'", (done) => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateWithNotificationPayload({userID: "test@example.com", qrURL: "https://example.com/mobile/auth#accessID"}, "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["oidc"]);
            done();
        });
    });

    it("should fail w/o user ID", (done) => {
        client.authenticateWithNotificationPayload({qrURL: "https://example.com/mobile/auth#accessID"}, "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid push notification payload");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail w/o QR URL", (done) => {
        client.authenticateWithNotificationPayload({userID: "test@example.com"}, "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid push notification payload");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client generateQuickCode", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'reg-code'", (done) => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, {});
        sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });

        client.generateQuickCode("test@example.com", "1234", (err, data) => {
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

    it("should fail on _authentication error", (done) => {
        sinon.stub(client, "_authentication").yields(new Error("Authentication fail"), null);

        client.generateQuickCode("test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Authentication fail");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail on verification/quickcode request error", (done) => {
        sinon.stub(client, "_authentication").yields(null, {});
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.generateQuickCode("test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
        client.http.request.restore && client.http.request.restore();
    });
});
