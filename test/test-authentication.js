if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client authenticate", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "ACTIVATED"
        });
    });

    it("should call errorCb w/o userId", function (done) {
        mfa.authenticate("", "", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
            done();
        });
    });

    it("should go through the authentication flow", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startAuthenticationStub = sinon.stub(mfa, "startAuthentication").yields(true);
        var finishAuthenticationStub = sinon.stub(mfa, "finishAuthentication").yields(true);

        mfa.authenticate("test@example.com", "1234", function (data) {
            expect(initStub.calledOnce).to.be.true;
            expect(startAuthenticationStub.calledOnce).to.be.true;
            expect(finishAuthenticationStub.calledOnce).to.be.true;
            done();
        }, function (err) {
            throw Error(err);
        });

        mfa.init.restore && mfa.init.restore();
        mfa.startAuthentication.restore && mfa.startAuthentication.restore();
        mfa.finishAuthentication.restore && mfa.finishAuthentication.restore();
    });
});

describe("Mfa Client _getPass1", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("shoud make a request for first pass", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_1").returns(0);

        mfa._getPass1("test@example.com", "1234", [], [], function () {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0]).to.be.an.object;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass1");
            expect(requestStub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_1").returns(0);

        mfa._getPass1("test@example.com", "1234", [], [], function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_1").returns(-14);

        mfa._getPass1("test@example.com", "1234", [], [], function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa.mpin.CLIENT_1.restore && mfa.mpin.CLIENT_1.restore();
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
        sinon.stub(mfa.mpin, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", "yHex", [], [], false, function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.getCalls()[0].args[0]).to.be.an.object;
            expect(stub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass2");
            expect(stub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", "yHex", [], [], false, function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should pass error to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_2").returns(-14);

        mfa._getPass2("test@example.com", "yHex", [], [], false, function (err, data) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    it("should make a request for OTP", function (done) {
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa.mpin, "CLIENT_2").returns(0);

        mfa._getPass2("test@example.com", "yHex", [], [], true, function (err, data) {
            expect(stub.calledOnce).to.be.true;
            done();
        });

    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        mfa.mpin.CLIENT_2.restore && mfa.mpin.CLIENT_2.restore();
    });
});

describe("Mfa Client _getPass", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("shoud call _getPass1 and _getPass2", function (done) {
        var getPass1Stub = sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        var getPass2Stub = sinon.stub(mfa, "_getPass2").yields(null, { success: true });

        mfa._getPass("test@example.com", "1234", false, function () {
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(mfa, "_getPass1").yields({ error: true }, null);

        mfa._getPass("test@example.com", "1234", false, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(mfa, "_getPass1").yields(null, { success: true });
        sinon.stub(mfa, "_getPass2").yields({ error: true }, null);

        mfa._getPass("test@example.com", "1234", false, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        mfa._getPass1.restore && mfa._getPass1.restore();
        mfa._getPass2.restore && mfa._getPass2.restore();
    });
});

describe("Mfa Client startAuthentication", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should call the error callback when there is an error", function (done) {
        sinon.stub(mfa, "_getPass").yields({ error: true }, null);

        mfa.startAuthentication("test@example.com", "1234", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        sinon.stub(mfa, "_getPass").yields(null, { success: true });

        mfa.startAuthentication("test@example.com", "1234", function (data) {
            expect(data).to.exist;
            done();
        }, function (err) {
            throw new Error(err);
        });
    });

    afterEach(function () {
        mfa._getPass.restore && mfa._getPass.restore();
    });
});

describe("Mfa Client finishAuthentication", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
        mfa.options.settings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa.finishAuthentication("test@example.com", "authOTT", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa.finishAuthentication("test@example.com", "authOTT", function (data) {
            expect(data).to.exist;
            done();
        }, function (err) {
            throw new Error(err);
        });
    });

    it("should mark an identity as revoked", function (done) {
        sinon.stub(mfa, "request").yields({ status: 410 }, null);

        mfa.finishAuthentication("test@example.com", "authOTT", function (data) {
            throw new Error(data);
        }, function (err) {
            expect(err).to.exist;
            expect(mfa.users.get("test@example.com", "state")).to.equal(mfa.users.states.revoked);
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
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

    it("should return call errorCb w/o userId", function (done) {
        mfa.fetchOTP("", "", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.name).to.equal("IdentityError");
            done();
        });
    });

    it("should call the error callback when there is an error", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getPass").yields({ error: true }, null);

        mfa.fetchOTP("test@example.com", "1234", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getPass").yields(null, { success: true });

        mfa.fetchOTP("test@example.com", "1234", function (data) {
            // Called twice for init and authenticate
            expect(requestStub.callCount).to.equal(2);
            expect(data).to.exist;
            done();
        }, function (err) {
            throw new Error(err);
        });
    });

    it("should call the error callback on authenticate error", function (done) {
        sinon.stub(mfa, "_getPass").yields(null, { success: true });
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 400 }, null);

        mfa.fetchOTP("test@example.com", "1234", function (data) {
            throw new Error(err);
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should mark the identity as revoked on authenticate error 410", function (done) {
        sinon.stub(mfa, "_getPass").yields(null, { success: true });
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        requestStub.onFirstCall().yields(null, { success: true });
        requestStub.onSecondCall().yields({ error: true, status: 410 }, null);

        var userWriteSpy = sinon.spy(mfa.users, "write");

        mfa.fetchOTP("test@example.com", "1234", function (data) {
            throw new Error(err);
        }, function (err) {
            expect(err).to.exist;
            expect(userWriteSpy.calledOnce).to.be.true;
            expect(userWriteSpy.getCalls()[0].args[0]).to.equal("test@example.com");
            expect(userWriteSpy.getCalls()[0].args[1].state).to.equal("REVOKED");
            done();
        });
    });

    afterEach(function () {
        mfa._getPass.restore && mfa._getPass.restore();
        mfa.request.restore && mfa.request.restore();
    });
});
