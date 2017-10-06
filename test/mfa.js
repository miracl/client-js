if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
    var inits = require("./init");
}

describe("Mfa Client", function() {
    it("should throw Error w/o init server", function () {
        expect(function () {
            var mfa = new Mfa();
        }).to.throw(Object).that.deep.equals({ code: "MISSING_SERVER", description: "Missing server parameter" });
    });

    it("should throw Error w/o customer", function () {
        expect(function () {
            var mfa = new Mfa({
                server: inits.testData.init.server
            });
        }).to.throw(Object).that.deep.equals({ code: "MISSING_CUSTOMER_ID", description: "Missing customer ID" });
    });

    it("should return Instance of Mfa", function () {
        var mfa = new Mfa(inits.testData.init);
        expect(mfa).to.be.an.instanceof(Mfa);
    });
});

describe("Mfa Client logger", function() {
    var mfa, spy;
    before(function () {
        inits.testData.init.debug = 1;
        mfa = new Mfa(inits.testData.init);
    });

    it("should call console info", function () {
        spy = sinon.spy();
        console.info = spy;
        mfa.log("message")
        expect(spy.calledOnce).to.be.true;
    });

    it("should call console error", function () {
        spy = sinon.spy();
        console.error = spy;
        mfa.log("message", true)
        expect(spy.calledOnce).to.be.true;
    });

    after(function () {
        mfa.restore();
        delete(inits.testData.init.debug);
    });
});

describe("Mfa Client init", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should fire errorCb, when have problem with _getSettings", function (done) {
        sinon.stub(mfa, '_getSettings').yields({ error: true }, null);
        mfa.init(function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should fire successCb, when fetch _getSettings", function (done) {
        sinon.stub(mfa, '_getSettings').yields(null, { success: true });
        mfa.init(function successCb(success) {
            expect(success).to.exist;
            done();
        }, function errorCb(err) {});
    });

    afterEach(function() {
        mfa._getSettings.restore && mfa._getSettings.restore();
    });
});

describe("Mfa Client setAccessId", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should set access id", function () {
        mfa.setAccessId("test");
        expect(mfa.accessId).to.equal("test");
    });
});

describe("Mfa Client _getSettings", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should store server settings", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._getSettings(function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should store server settings", function(done) {
        sinon.stub(mfa, "request").yields(null, inits.testData.settings);

        mfa._getSettings(function(successData) {
            expect(mfa.options.settings).to.deep.equal(inits.testData.settings);
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client startRegistration", function() {
    var mfa;

    before(function () {
        localStorage.clear();
        mfa = new Mfa(inits.testData.init);
    });

    it("should call errorCb with MISSING_USERID when called w/o userId", function (done) {
        mfa.startRegistration("", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal("MISSING_USERID");
            done();
        })
    });

    it("should call errorCb with WRONG_FLOW when user is not suitable", function (done) {
        sinon.stub(mfa.users, "suitableFor").returns(false);

        mfa.startRegistration(inits.testData.userId, function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal("WRONG_FLOW");
            done()
        });

        mfa.users.suitableFor.restore && mfa.users.suitableFor.restore();
    });

    it("should fire errorCb, when have problem with _registration", function (done) {
        sinon.stub(mfa, '_registration').yields({}, null);
        mfa.startRegistration(inits.testData.userId, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });

        mfa._registration.restore && mfa._registration.restore();
    });

    it("should fire successCb, when _registration passed successful", function (done) {
        sinon.stub(mfa, '_registration').yields(null, {});

        mfa.startRegistration(inits.testData.userId, function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) {
            throw new Error(err.code);
        });

        mfa._registration.restore && mfa._registration.restore();
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
    });
});

describe("Mfa Client _registration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._registration(inits.testData.userId, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should store userId, when register successful", function(done) {
        sinon.stub(mfa, 'request').yields(null, {});

        mfa._registration(inits.testData.userId, function(err, data) {
            expect(mfa.users.exists(inits.testData.userId)).to.be.true;
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client confirmRegistration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should fire errorCb when _getSecret1 return 401 & error should be IDENTITY_NOT_VERIFIED", function (done) {
        sinon.stub(mfa, '_getSecret1').yields({ status: 401 }, null);
        sinon.stub(mfa.users, "suitableFor").returns(true);

        mfa.confirmRegistration(inits.testData.userId, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            expect(err.code).to.equal('IDENTITY_NOT_VERIFIED');
            done();
        });
    });

    it("should fire errorCb when _getSecret1 returns another error", function (done) {
        sinon.stub(mfa, '_getSecret1').yields({ status: 400 }, null);
        sinon.stub(mfa.users, "suitableFor").returns(true);

        mfa.confirmRegistration(inits.testData.userId, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire errorCb when _getSecret1 return other error", function (done) {
        sinon.stub(mfa, '_getSecret1').yields({}, null);

        mfa.confirmRegistration(inits.testData.userId, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb when _getSecret1 return Ok", function (done) {
        sinon.stub(mfa, '_getSecret').yields(null, {});
        sinon.stub(mfa.users, "suitableFor").returns(true);

        mfa.confirmRegistration(inits.testData.userId, function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) {
            throw Error(err);
        });

    });

    it("should return MISSING_USERID when try to call confirmRegistration w/o userId", function (done) {
        mfa.confirmRegistration("", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal('MISSING_USERID');
            done();
        })
    });

    afterEach(function() {
        mfa._getSecret.restore && mfa._getSecret.restore();
        mfa._getSecret1.restore && mfa._getSecret1.restore();
        mfa.users.suitableFor.restore && mfa.users.suitableFor.restore();
    });
});

describe("Mfa Client _getSecret", function() {
    var mfa, spy;

    before(function () {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
        spy = sinon.spy();
    });

    it("should return error, when signature request fail", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._getSecret(inits.testData.userId, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error, when signature2 request fail", function(done) {
        var stub = sinon.stub(mfa, 'request');
        stub.onCall(0).yields(null, {});
        stub.onCall(1).yields({}, null);

        mfa._getSecret(inits.testData.userId, function(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call addShares with CS and CSShare", function(done) {
        var stub = sinon.stub(mfa, 'request');
        stub.onCall(0).yields(null, inits.testData.cs1);
        stub.onCall(1).yields(null, inits.testData.cs2);

        MPINAuth = {};
        MPINAuth.addShares = spy;

        mfa._getSecret(inits.testData.userId, function(err) {
            expect(spy.calledOnce).to.be.true;
            expect(spy.getCalls()[0].args[0]).to.equal(inits.testData.cs1.clientSecretShare);
            expect(spy.getCalls()[0].args[1]).to.equal(inits.testData.cs2.clientSecret);
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client finishRegistration", function() {
    var mfa, userData;

    beforeEach(function () {
        mfa = new Mfa(inits.testData.init);
        userData = inits.testData.users[inits.testData.userId];
        mfa.users.add(inits.testData.userId, userData);
    });

    it("should return MISSING_USERID when called w/o userId", function (done) {
        mfa.finishRegistration("", "", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal('MISSING_USERID');
            done();
        });
    });

    it("should call errorCb with WRONG_FLOW when user is not suitable", function (done) {
        sinon.stub(mfa.users, "suitableFor").returns(false);

        mfa.finishRegistration(inits.testData.userId, "1234", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal("WRONG_FLOW");
            done();
        });

        mfa.users.suitableFor.restore && mfa.users.suitableFor.restore();
    });

    it("should hash userPin if it is not a number", function (done) {
        var spy = sinon.spy(mfa, "toHash");
        MPINAuth = {};
        MPINAuth.calculateMPinToken = function() {};

        mfa.finishRegistration(inits.testData.userId, "testPin", function () {
            expect(spy.calledOnce).to.be.true;
            done();
        });
    });

    it("should call calculateMpinToken with mpinId, Pin & csHex", function (done) {
        var spy = sinon.spy();
        MPINAuth = {};
        MPINAuth.calculateMPinToken = spy;

        mfa.finishRegistration(inits.testData.userId, "1234", function (data) {
            expect(spy.calledOnce).to.be.true;
            expect(spy.getCalls()[0].args[0]).to.equal(userData.mpinId);
            expect(spy.getCalls()[0].args[1]).to.equal("1234");
            expect(spy.getCalls()[0].args[2]).to.equal(userData.csHex);
            done();
        });
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
        mfa.users.delete(inits.testData.userId);
    });
});

describe("Mfa Client register", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should go through the registration flow", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startRegistrationStub = sinon.stub(mfa, "startRegistration").yields(true);
        var confirmRegistrationStub = sinon.stub(mfa, "confirmRegistration").yields(true);
        var finishRegistrationStub = sinon.stub(mfa, "finishRegistration").yields(true);

        mfa.register(inits.testData.userId, function (passPin) {
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

        mfa.init.restore && mfa.init.restore();
        mfa.startRegistration.restore && mfa.startRegistration.restore();
        mfa.confirmRegistration.restore && mfa.confirmRegistration.restore();
        mfa.finishRegistration.restore && mfa.finishRegistration.restore();
    });
});

describe("Mfa Client authenticate", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
        userData = inits.testData.users[inits.testData.userId];
        mfa.users.add(inits.testData.userId, userData);
    });

    it("should return MISSING_USERID w/o userId", function (done) {
        mfa.authenticate("", "", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal('MISSING_USERID');
            done();
        });
    });

    it("should go through the authentication flow", function (done) {
        var initStub = sinon.stub(mfa, "init").yields(true);
        var startAuthenticationStub = sinon.stub(mfa, "startAuthentication").yields(true);
        var finishAuthenticationStub = sinon.stub(mfa, "finishAuthentication").yields(true);

        mfa.authenticate(inits.testData.userId, "1234", function (data) {
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
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;

        MPINAuth = { pass1Request: function () {} };
        sinon.stub(MPINAuth, 'pass1Request').returns({ success: true }, null);
    });

    it("shoud make a request for first pass", function (done) {
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getPass1(inits.testData.userId, "1234", function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.getCalls()[0].args[0]).to.be.an.object;
            expect(stub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass1");
            expect(stub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getPass1(inits.testData.userId, "1234", function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client _getPass2", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;

        MPINAuth = { pass2Request: function () {} };
    });

    it("shoud make a request for second pass", function (done) {
        sinon.stub(MPINAuth, 'pass2Request').returns({ error: true }, null);
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getPass2(inits.testData.userId, "yHex", false, function () {
            expect(stub.calledOnce).to.be.true;
            expect(stub.getCalls()[0].args[0]).to.be.an.object;
            expect(stub.getCalls()[0].args[0].url).to.equal("https://api.miracl.net/rps/pass2");
            expect(stub.getCalls()[0].args[0].type).to.equal("POST");
            done();
        });
    });

    it("should pass response to callback", function (done) {
        sinon.stub(MPINAuth, 'pass2Request').returns({ error: true }, null);
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa._getPass2(inits.testData.userId, "1234", false, function (err, data) {
            expect(data).to.exist;
            expect(data.success).to.be.true;
            done();
        });
    });

    it("should make a request for OTP", function (done) {
        var stub = sinon.stub(mfa, "request").yields(null, { success: true });

        var pass2RequestStub = sinon.stub(MPINAuth, "pass2Request").returns({success: true});

        mfa._getPass2(inits.testData.userId, "1234", true, function (err, data) {
            expect(stub.calledOnce).to.be.true;
            expect(pass2RequestStub.calledOnce).to.be.true;
            expect(pass2RequestStub.getCalls()[0].args[1]).to.be.true;
            done();
        });

    });

    afterEach(function () {
        mfa.request.restore && mfa.request.restore();
        MPINAuth.pass2Request.restore && MPINAuth.pass2Request.restore();
    });
});

describe("Mfa Client _getPass", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
    });

    it("shoud call _getPass1 and _getPass2", function (done) {
        var getPass1Stub = sinon.stub(mfa, '_getPass1').yields(null, { success: true });
        var getPass2Stub = sinon.stub(mfa, '_getPass2').yields(null, { success: true });

        mfa._getPass(inits.testData.userId, "1234", false, function () {
            expect(getPass1Stub.calledOnce).to.be.true;
            expect(getPass2Stub.calledOnce).to.be.true;
            done();
        });
    });

    it("should call callback with error when _getPass1 fails", function (done) {
        sinon.stub(mfa, '_getPass1').yields({ error: true }, null);

        mfa._getPass(inits.testData.userId, "1234", false, function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call callback with error when _getPass2 fails", function (done) {
        sinon.stub(mfa, '_getPass1').yields(null, { success: true });
        sinon.stub(mfa, '_getPass2').yields({ error: true }, null);

        mfa._getPass(inits.testData.userId, "1234", false, function (err, data) {
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
        mfa = new Mfa(inits.testData.init);
    });

    it("should call the error callback when there is an error", function (done) {
        sinon.stub(mfa, "_getPass").yields({ error: true }, null);

        mfa.startAuthentication(inits.testData.userId, "1234", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        sinon.stub(mfa, "_getPass").yields(null, { success: true });

        mfa.startAuthentication(inits.testData.userId, "1234", function (data) {
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
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);

        mfa.finishAuthentication(inits.testData.userId, "authOTT", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after successful request", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });

        mfa.finishAuthentication(inits.testData.userId, "authOTT", function (data) {
            expect(data).to.exist;
            done();
        }, function (err) {
            throw new Error(err);
        });
    });

    it("should mark an identity as revoked", function (done) {
        sinon.stub(mfa, "request").yields({ status: 410 }, null);

        mfa.finishAuthentication(inits.testData.userId, "authOTT", function (data) {
            throw new Error(data);
        }, function (err) {
            expect(err).to.exist;
            expect(mfa.users.get(inits.testData.userId, "state")).to.equal(mfa.users.states.revoked);
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
        mfa = new Mfa(inits.testData.init);
        userData = inits.testData.users[inits.testData.userId];
        mfa.users.add(inits.testData.userId, userData);
    });

    it("should return MISSING_USERID w/o userId", function (done) {
        mfa.fetchOTP("", "", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal('MISSING_USERID');
            done();
        });
    });

    it("should call the error callback when there is an error", function (done) {
        sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getPass").yields({ error: true }, null);

        mfa.fetchOTP(inits.testData.userId, "1234", function (data) {
            done();
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call the success callback after getting the passes", function (done) {
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });
        sinon.stub(mfa, "_getPass").yields(null, { success: true });

        mfa.fetchOTP(inits.testData.userId, "1234", function (data) {
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
        requestStub.onSecondCall().yields({ error: true, status: 410 }, null);

        mfa.fetchOTP(inits.testData.userId, "1234", function (data) {
            throw new Error(err);
        }, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        mfa._getPass.restore && mfa._getPass.restore();
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client request", function() {
    var mfa, server, requests = [];

    before(function () {
        mfa = new Mfa(inits.testData.init);

        var xhr = global.XMLHttpRequest = sinon.useFakeXMLHttpRequest();
        xhr.onCreate = function (xhr) {
            requests.push(xhr);
        };
    });

    it("should return error missing CB", function () {
        var res = mfa.request({ url: "reqUrl" });

        expect(res).to.exist;
        expect(res.code).to.equal('MISSING_CALLBACK');
    });

    it("should handle successful JSON response", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-json-get"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "{ \"test\": 1 }");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, null, { test: 1 });
    });

    it("should handle successful text response", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-json-get"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "test");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, null, "test");
    });

    it("should make a post request", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-json-get",
            type: "POST",
            data: { test: 1}
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "{ \"test\": 1 }");

        expect(callback.callCount).to.equal(1);
    });

    it("should handle error response", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-error"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(400, { }, "");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, { code: "REQUEST_ERROR", description: "Bad Request", status: 400 }, null);
    });

    it("should handle aborted request", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-abort"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(0, { }, "");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, { code: "REQUEST_ABORTED", description: "The request was aborted", status: 0 }, null);
    });
});
