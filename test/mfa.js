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

    it("should throw Error w/o distributor", function () {
        expect(function () {
            var mfa = new Mfa({
                server: inits.testData.init.server
            });
        }).to.throw(Object).that.deep.equals({ code: "MISSING_DISTRIBUTOR", description: "Missing Distributor" });
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

describe("Mfa Client restartRegistration", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(inits.testData.init);
    });

    it("should return MISSING_USERID when try to call restartRegistration w/o userId", function (done) {
        mfa.restartRegistration("", function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal('MISSING_USERID');
            done();
        })
    });

    it("should call errorCb with WRONG_FLOW when user is not suitable", function (done) {
        sinon.stub(mfa.users, "suitableFor").returns(false);

        mfa.restartRegistration(inits.testData.userId, function () {}, function (err) {
            expect(err).to.exist;
            expect(err.code).to.equal("WRONG_FLOW");
            done()
        });

        mfa.users.suitableFor.restore && mfa.users.suitableFor.restore();
    });

    it("should fire errorCb, when have problem with _registration", function (done) {
        sinon.stub(mfa, '_registration').yields({ error: true }, null);
        sinon.stub(mfa.users, "suitableFor").returns(true);

        mfa.restartRegistration(inits.testData.userId, function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb, when _registration passed successful", function (done) {
        sinon.stub(mfa, '_registration').yields(null, {});
        sinon.stub(mfa.users, "suitableFor").returns(true);

        mfa.restartRegistration(inits.testData.userId, function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) {
            throw Error(err);
        });
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
        mfa.users.suitableFor.restore && mfa.users.suitableFor.restore();
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

        mfa.register(inits.testData.userId, "1234", function (confirm) {
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
        sinon.assert.calledWith(callback, { status: 400 }, null);
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
        sinon.assert.calledWith(callback, { status: 0 }, null);
    });
});
