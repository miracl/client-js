if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
    var inits = require("./init");
}

describe("Mfa Client", function() {
    it("should return Error w/o init server", () => {
        var mfa = new Mfa();
        expect(mfa).to.be.an.instanceof(Error);
    });

    it("should return Error w/o distributor", () => {
        var mfa = new Mfa({
            server: inits.testData.server
        });
        expect(mfa).to.be.an.instanceof(Error);
    });

    it("should return Instance of Mfa", () => {
        var mfa = new Mfa(inits.testData.init);
        expect(mfa).to.be.an.instanceof(Mfa);
    });
});

describe("Mfa Client logger", function () {
    var mfa, spy;
    before(() => {
        inits.testData.init.debug = 1;
        spy = sinon.spy();
        console.info = () => {};
        mfa = new Mfa(inits.testData.init);
    });

    it("should call console info", () => {
        console.info = spy;
        mfa.log("message")
        expect(spy.calledOnce).to.be.true;
    });

    after(() => {
        mfa.restore();
        delete (inits.testData.init.debug);
    });
});

describe("Mfa Client init method", function () {
    var mfa;

    before(() => {
        mfa = new Mfa(inits.testData.init);
    });

    it("should fire errorCb, when have problem with _getSettings", (done) => {
        sinon.stub(mfa, '_getSettings').yields({error: true}, null);
        mfa.init(function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb, when fetch _getSettings", (done) => {
        sinon.stub(mfa, '_getSettings').yields(null, {});
        mfa.init(function successCb(successData) {
            expect(successData).to.exist;
            done();
        }, function errorCb(err) { });
    });

    afterEach(function() {
        mfa._getSettings.restore && mfa._getSettings.restore();
    });
});

describe("Mfa Client _getSettings", function() {
    var mfa;

    before(() => {
        mfa = new Mfa(inits.testData.init);
    });

    it("should store server settings", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._getSettings(function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should store server settings", function(done) {
        sinon.stub(mfa, 'request').yields(null, inits.testData.settings);

        mfa._getSettings(function (successData) {
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

    before(() => {
        mfa = new Mfa(inits.testData.init);
    });

    it("should fire errorCb, when have problem with _registration", (done) => {
        sinon.stub(mfa, '_registration').yields({}, null);
        mfa.startRegistration(inits.testData.userId, function successCb(data) { }, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb, when _registration passed successful", (done) => {
        sinon.stub(mfa, '_registration').yields(null, {});
        mfa.startRegistration(inits.testData.userId, function successCb(data) { 
            expect(data).to.exist;
            done();
        }, function errorCb(err) {});
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
    });
});

describe("Mfa Client _registration", function() {
    var mfa;

    before(() => {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
    });

    it("should return error, when register request fail", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._registration(inits.testData.userId, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should store userId, when register successful", function(done) {
        sinon.stub(mfa, 'request').yields(null, {});

        mfa._registration(inits.testData.userId, function (err, data) {
            let userExist;
            userExist = mfa.checkUserExists(inits.testData.userId);
            expect(userExist).to.be.true;
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client confirmRegistration", function() {
    var mfa;

    before(() => {
        mfa = new Mfa(inits.testData.init);
    });



    it("should fire errorCb, when _getSecret1 return 401 & error should be IDENTITY_NOT_VERIFIED", (done) => {
        sinon.stub(mfa, '_getSecret1').yields({status: 401}, null);
        mfa.confirmRegistration(inits.testData.userId, function successCb(data) { }, function errorCb(err) {
            expect(err).to.exist;
            expect(err.code).to.equal('IDENTITY_NOT_VERIFIED');
            done();
        });
    });

    it("should fire errorCb, when _getSecret1 return other error", (done) => {
        sinon.stub(mfa, '_getSecret1').yields({}, null);
        mfa.confirmRegistration(inits.testData.userId, function successCb(data) { }, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });


    it("should fire successCb, when _getSecret1 return Ok", (done) => {
        sinon.stub(mfa, '_getSecret').yields(null, {});
        mfa.confirmRegistration(inits.testData.userId, function successCb(data) {
            expect(data).to.exist;
            done();
        }, function errorCb(err) { });
    });

    afterEach(function() {
        mfa._getSecret.restore && mfa._getSecret.restore();
        mfa._getSecret1.restore && mfa._getSecret1.restore();
    });
});

describe("Mfa Client _getSecret", function() {
    var mfa, spy;

    before(() => {
        mfa = new Mfa(inits.testData.init);
        mfa.options.settings = inits.testData.settings;
        spy = sinon.spy();
    });

    it("should return error, when signature request fail", function(done) {
        sinon.stub(mfa, 'request').yields({}, null);

        mfa._getSecret(inits.testData.userId, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should return error, when signature2 request fail", function(done) {
        var stub = sinon.stub(mfa, 'request');
        stub.onCall(0).yields(null, {});
        stub.onCall(1).yields({}, null);

        mfa._getSecret(inits.testData.userId, function (err) {
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
        mfa._getSecret(inits.testData.userId, function (err) {
            expect(spy.calledOnce).to.be.true;
            expect(spy.getCalls()[0].args[0]).to.equal(inits.testData.cs1.clientSecret);
            expect(spy.getCalls()[0].args[1]).to.equal(inits.testData.cs2.clientSecretShare);
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client restartRegistration", function() {
    var mfa;

    before(() => {
        mfa = new Mfa(inits.testData.init);
    });

    it("should fire errorCb, when have problem with _registration", (done) => {
        sinon.stub(mfa, '_registration').yields({}, null);
        mfa.restartRegistration(inits.testData.userId, function successCb(data) { }, function errorCb(err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should fire successCb, when _registration passed successful", (done) => {
        sinon.stub(mfa, '_registration').yields(null, {});
        mfa.restartRegistration(inits.testData.userId, function successCb(data) { 
            expect(data).to.exist;
            done();
        }, function errorCb(err) {});
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
    });
});

describe("Mfa Client finishRegistration", function() {
    var mfa, userData;

    before(() => {
        mfa = new Mfa(inits.testData.init);
        userData = inits.testData.users.data[inits.testData.userId];
        
        mfa.addUser(inits.testData.userId, userData);
    });

    it("should hash userPin if it is not a number", function () {
        var spy = sinon.spy(mfa, "toHash");
        MPINAuth = {};
        MPINAuth.calculateMPinToken = function () {};
        mfa.finishRegistration(inits.testData.userId, "testPin");
        expect(spy.calledOnce).to.be.true;
    });

    it("should call calculateMpinToken with mpinId, Pin & csHex", function () { 
        var spy = sinon.spy();
        MPINAuth = {};
        MPINAuth.calculateMPinToken = spy;
        mfa.finishRegistration(inits.testData.userId, "1234");


        expect(spy.calledOnce).to.be.true;
        expect(spy.getCalls()[0].args[0]).to.equal(userData.mpinId);
        expect(spy.getCalls()[0].args[1]).to.equal("1234");
        expect(spy.getCalls()[0].args[2]).to.equal(userData.csHex);
    });

    afterEach(function() {
        mfa._registration.restore && mfa._registration.restore();
    });
});