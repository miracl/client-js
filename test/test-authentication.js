if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client _getPass1", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("shoud make a request for first pass", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_1").returns(0);

        mfa._getPass1("test@example.com", "1234", ["oidc"], [], [], function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0]).to.be.an.object;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass1");
            expect(requestStub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_1").returns(0);

        mfa._getPass1("test@example.com", "1234", ["oidc"], [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_1").returns(-14);

        mfa._getPass1("test@example.com", "1234", ["oidc"], [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_1").returns(0);

        mfa._getPass1("test@example.com", "1234", ["dvs-auth"], [], [], function (err, data) {
            expect(requestStub.getCalls()[0].args[0].data.scope).to.deep.equal(["dvs-auth"]);
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa.crypto().MPIN.CLIENT_1.restore && mfa.crypto().MPIN.CLIENT_1.restore();
    });
});

describe("Mfa Client _getPass2", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("shoud make a request for second pass", function (done) {
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", ["oidc"], "yHex", [], [], function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.getCalls()[0].args[0]).to.be.an.object;
            expect(stub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass2");
            expect(stub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", ["oidc"], "yHex", [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_2").returns(-14);

        mfa._getPass2("test@example.com", ["oidc"], "yHex", [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    it("should make a request for OTP", function (done) {
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", ["otp"], "yHex", [], [], function (err, data) {
            expect(stub.calledOnce).to.be.true;
            done();
        });
    });

    it("should handle dvs scope", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.crypto().MPIN, "CLIENT_2").returns(0);

        mfa.dvsUsers.write("test@example.com", {
            mpinId: "thisIsDvsId",
            state: "ACTIVATED"
        });

        mfa._getPass2("test@example.com", ["dvs-auth"], "yHex", [], [], function (err, data) {
            expect(requestStub.getCalls()[0].args[0].data.mpin_id).to.equal("thisIsDvsId");
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa.crypto().MPIN.CLIENT_2.restore && mfa.crypto().MPIN.CLIENT_2.restore();
    });
});

describe("Mfa Client _finishAuthentication", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should mark an identity as revoked", function (done) {
        sinon.stub(mfa, "request").yields({ status: 410 }, null);

        mfa._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err, data) {
            expect(err).to.exist;
            expect(mfa.users.get("test@example.com", "state")).to.equal(mfa.users.states.revoked);
            done();
        });
    });

    it("should renew identity secret if requested", function(done) {
        sinon.stub(mfa, "request").yields(null, { success: true, renewSecret: { test: 1 } });
        var renewSecretStub = sinon.stub(mfa, "_renewSecret").yields(null);

        mfa._finishAuthentication("test@example.com", 1234, ["oidc"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should renew DVS secret if requested", function(done) {
        sinon.stub(mfa, "request").yields(null, { success: true, dvsRegister: { test: 1 } });
        var renewDvsSecretStub = sinon.stub(mfa, "_renewDvsSecret").yields(null);

        mfa._finishAuthentication("test@example.com", 1234, ["dvs-auth"], "authOTT", function (err) {
            expect(err).to.be.null;
            expect(renewDvsSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _renewSecret", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should renew the identity secret", function (done) {
        sinon.stub(mfa, "request").yields(null, {});
        var getSecret2Stub = sinon.stub(mfa, "_getSecret2").yields(null);
        var createIdentityStub = sinon.stub(mfa, "_createIdentity").yields(null);
        var authenticateStub = sinon.stub(mfa, "authenticate").yields(null);

        mfa._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.be.null;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            expect(authenticateStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call error callback on getSecret2 error", function (done) {
        sinon.stub(mfa, "_getSecret2").yields({ error: true });

        mfa._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call error callback on createIdentity error", function (done) {
        sinon.stub(mfa, "_getSecret2").yields(null);
        sinon.stub(mfa, "_createIdentity").yields({ error: true });

        mfa._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call error callback on authenticate error", function (done) {
        sinon.stub(mfa, "_getSecret2").yields(null);
        sinon.stub(mfa, "_createIdentity").yields(null);
        sinon.stub(mfa, "authenticate").yields({ error: true });

        mfa._renewSecret("test@example.com", 1234, { cs2url: "https://test/cs2url"}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa._getSecret2.restore && mfa._getSecret2.restore();
        mfa._createIdentity.restore && mfa._createIdentity.restore();
        mfa.authenticate.restore && mfa.authenticate.restore();
    });
});

describe("Mfa Client _authentication", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should fail w/o userId", function (done) {
        mfa._authentication("", "", ["otp"], function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
            done();
        });
    });

    it("should go through the authentication flow", function (done) {
        var initStub = sinon.stub(mfa, "_init").yields(null, true);
        var getPass1Stub = sinon.stub(mfa, "_getPass1").yields(null, {});
        var getPass2Stub = sinon.stub(mfa, "_getPass2").yields(null, {});
        var finishAuthenticationStub = sinon.stub(mfa, "_finishAuthentication").yields(null, true);

        mfa._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.be.null;
            expect(initStub.calledOnce).to.be.true;
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(mfa, "_init").yields(null, true);
        sinon.stub(mfa, "_getPass1").yields({ error: true }, null);

        mfa._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(mfa, "_init").yields(null, true);
        sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        sinon.stub(mfa, "_getPass2").yields({ error: true }, null);

        mfa._authentication("test@example.com", "1234", ['oidc'], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        sinon.stub(mfa, "_getPass2").yields(null, { success: true });

        mfa._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.be.null;
            // Called twice for init and authenticate
            expect(requestStub.callCount).to.equal(2);
            expect(data).to.exist;
            done();
        });
    });

    it("should call the error callback on authenticate error", function (done) {
        sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        sinon.stub(mfa, "_getPass2").yields(null, { success: true });
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 400 }, null);

        mfa._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error 410", function (done) {
        sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        sinon.stub(mfa, "_getPass2").yields(null, { success: true });
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 410 }, null);

        var userWriteSpy = sinon.spy(mfa.users, "write");

        mfa._authentication("test@example.com", "1234", ["otp"], function (err, data) {
            expect(err).to.exist;
            expect(userWriteSpy.calledOnce).to.be.true;
            expect(userWriteSpy.getCalls()[0].args[0]).to.equal("test@example.com");
            expect(userWriteSpy.getCalls()[0].args[1].state).to.equal("REVOKED");
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa._init.restore && mfa._init.restore();
        mfa._getPass1.restore && mfa._getPass1.restore();
        mfa._getPass2.restore && mfa._getPass2.restore();
        mfa._finishAuthentication.restore && mfa._finishAuthentication.restore();
    });
});

describe("Mfa Client authenticate", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'oidc'", function (done) {
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, { success: true });

        mfa.authenticate("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.getCalls()[0].args[2]).to.deep.equal(["oidc"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Mfa Client fetchOTP", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'otp'", function (done) {
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, { success: true });

        mfa.fetchOTP("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.getCalls()[0].args[2]).to.deep.equal(["otp"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Mfa Client fetchRegistrationCode", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'reg-code'", function (done) {
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, { success: true });

        mfa.fetchRegistrationCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.getCalls()[0].args[2]).to.deep.equal(["reg-code"]);
            done();
        });

        authenticationStub.restore();
    });
});

describe("Mfa Client fetchAuthCode", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call _authentication with scope 'authcode'", function (done) {
        var authenticationStub = sinon.stub(mfa, "_authentication").yields(null, { success: true });

        mfa.fetchAuthCode("test@example.com", "1234", function (err, data) {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.getCalls()[0].args[2]).to.deep.equal(["authcode"]);
            done();
        });

        authenticationStub.restore();
    });
});
