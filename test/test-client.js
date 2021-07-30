import Mfa from "../src/mfa.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Mfa Client", function() {
    it("should throw Error w/o options", function () {
        expect(function () {
            var mfa = new Mfa();
        }).to.throw("Missing options");
    });

    it("should throw Error w/o project ID", function () {
        expect(function () {
            var config = testData.init();
            delete config["projectId"];
            var mfa = new Mfa(config);
        }).to.throw("Missing project ID");
    });

    it("should throw Error w/o user storage", function () {
        expect(function () {
            var config = testData.init();
            delete config["userStorage"];
            var mfa = new Mfa(config);
        }).to.throw("Missing user storage object");
    });

    it("should return instance of Mfa", function () {
        var mfa = new Mfa(testData.init());
        expect(mfa).to.be.an.instanceof(Mfa);
    });

    it("should set default server address if there is none", function () {
        var config = testData.init();
        delete config["server"];
        var mfa = new Mfa(config);
        expect(mfa.options.server).to.equal("https://api.mpin.io");
    });

    it("should set default PIN length to 4 if there is none", function () {
        var config = testData.init();
        delete config["defaultPinLength"];
        var mfa = new Mfa(config);
        expect(mfa.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if less than 4", function () {
        var config = testData.init();
        config.defaultPinLength = 3;
        var mfa = new Mfa(config);
        expect(mfa.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if more than 6", function () {
        var config = testData.init();
        config.defaultPinLength = 7;
        var mfa = new Mfa(config);
        expect(mfa.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to provided value within range", function () {
        var config = testData.init();
        config.defaultPinLength = 5;
        var mfa = new Mfa(config);
        expect(mfa.options.defaultPinLength).to.equal(5);
    });
});

describe("Mfa Client _init", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should fire callback with error when settings can't be fetched", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);
        mfa._init(function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should fire successCb after fetching settings", function (done) {
        sinon.stub(mfa, "request").yields(null, testData.settings());
        mfa._init(function (err, success) {
            expect(err).to.be.null;
            expect(success).to.exist;
            expect(mfa.clientSettings).to.deep.equal(testData.settings());
            done();
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client setAccessId", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should set access id", function () {
        mfa.setAccessId("test");
        expect(mfa.accessId).to.equal("test");
    });
});

describe("Mfa Client fetchAccessId", function () {
    var mfa, sessionInfo;

    before(function () {
        mfa = new Mfa(testData.init());

        sessionInfo = {
            webOTT: 1,
            accessURL: "https://example.com/access",
            qrURL: "https://example.com#accessID"
        };
    });

    it("should make a request for access ID", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, sessionInfo);

        mfa.fetchAccessId("test@example.com", function (err, data) {
            expect(data).to.deep.equal(sessionInfo);
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(mfa, "request").yields(new Error("Error"), null);

        mfa.fetchAccessId("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should fail if response doesn't have all session data", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, {});

        mfa.fetchAccessId("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should store session info", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, sessionInfo);

        mfa.fetchAccessId("test@example.com", function (err, data) {
            expect(mfa.session).to.deep.equal(sessionInfo);
        });
    });

    it("should set the access ID", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, sessionInfo);

        mfa.fetchAccessId("test@example.com", function (err, data) {
            expect(mfa.accessId).to.equal("accessID");
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client fetchStatus", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should make a request for session status", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, { status: "new" });

        mfa.fetchStatus(function (err, data) {
            expect(data.status).to.equal("new");
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(mfa, "request").yields(new Error("Error"), null);

        mfa.fetchStatus(function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should fail if response doesn't have expected data", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, {});

        mfa.fetchStatus(function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client sendPushNotificationForAuth", function () {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should make a request to the pushauth endpoint", function () {
        var requestStub = sinon.stub(mfa, "request").yields(null, { webOTT: "test" });

        mfa.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(data).to.exist;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/pushauth?client_id=testClientID");
            expect(data.webOTT).to.equal("test");
        });
    });

    it("should fail when the request fails", function () {
        var requestStub = sinon.stub(mfa, "request").yields(new Error("Error"), null);

        mfa.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should return an error without an user ID", function () {
        mfa.sendPushNotificationForAuth(null, function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        mfa.request.restore && mfa.request.restore();
    });
});

describe("Mfa Client request", function() {
    var mfa, server, requests = [];

    before(function () {
        mfa = new Mfa(testData.init());

        var xhr = global.XMLHttpRequest = sinon.useFakeXMLHttpRequest();
        xhr.onCreate = function (xhr) {
            requests.push(xhr);
        };
    });

    it("should throw error missing callback", function () {
        expect(function () {
            mfa.request({ url: "reqUrl" });
        }).to.throw("Bad or missing callback");

        expect(function () {
            mfa.request({ url: "reqUrl" }, "string");
        }).to.throw("Bad or missing callback");
    });

    it("should throw error missing URL", function () {
        expect(function () {
            mfa.request({}, function () {});
        }).to.throw("Missing URL for request");
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

    it("should set Authorization Header", function () {
        requests = [];

        var callback = sinon.spy();
        mfa.request({
            url: "/test-auth",
            authorization: "Bearer test"
        }, callback);

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("Authorization");
        expect(requests[0].requestHeaders["Authorization"]).to.equal("Bearer test");
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
        expect(callback.firstCall.args[0].name).to.equal("RequestError");
        expect(callback.firstCall.args[1]).to.be.null;
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
        expect(callback.callCount).to.equal(1);
        expect(callback.firstCall.args[0].name).to.equal("RequestError");
        expect(callback.firstCall.args[0].message).to.equal("The request was aborted");
        expect(callback.firstCall.args[1]).to.be.null;
    });
});
