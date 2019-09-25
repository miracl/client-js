if (typeof require !== "undefined") {
    var expect = require("chai").expect;
    var sinon = require("sinon");
    var Mfa = require("../index");
}

describe("Mfa Client", function() {
    it("should throw Error w/o options", function () {
        expect(function () {
            var mfa = new Mfa();
        }).to.throw("Missing options");
    });

    it("should throw Error w/o init server", function () {
        expect(function () {
            var config = testData.init();
            delete config["server"];
            var mfa = new Mfa(config);
        }).to.throw("Missing server address");
    });

    it("should throw Error w/o customer", function () {
        expect(function () {
            var config = testData.init();
            delete config["customerId"];
            var mfa = new Mfa(config);
        }).to.throw("Missing customer ID");
    });

    it("should throw Error w/o user storage", function () {
        expect(function () {
            var config = testData.init();
            delete config["userStorage"];
            var mfa = new Mfa(config);
        }).to.throw("Missing user storage object");
    });

    it("should return Instance of Mfa", function () {
        var mfa = new Mfa(testData.init());
        expect(mfa).to.be.an.instanceof(Mfa);
    });

    it("should set default PIN length to 4 if there is none", function () {
        var config = testData.init();
        delete config["defaultPinLength"];
        var mfa = new Mfa(config);
        expect(mfa.options.client.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if less than 4", function () {
        var config = testData.init();
        config.defaultPinLength = 3;
        var mfa = new Mfa(config);
        expect(mfa.options.client.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if more than 6", function () {
        var config = testData.init();
        config.defaultPinLength = 7;
        var mfa = new Mfa(config);
        expect(mfa.options.client.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to provided value within range", function () {
        var config = testData.init();
        config.defaultPinLength = 5;
        var mfa = new Mfa(config);
        expect(mfa.options.client.defaultPinLength).to.equal(5);
    });
});

describe("Mfa Client init", function() {
    var mfa;

    before(function () {
        mfa = new Mfa(testData.init());
    });

    it("should fire errorCb when settings can't be fetched", function (done) {
        sinon.stub(mfa, "request").yields({ error: true }, null);
        mfa.init(function successCb(data) {}, function errorCb(err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should fire successCb after fetching settings", function (done) {
        sinon.stub(mfa, "request").yields(null, testData.settings());
        mfa.init(function successCb(success) {
            expect(success).to.exist;
            expect(mfa.options.settings).to.deep.equal(testData.settings());
            done();
        }, function errorCb(err) {});
    });

    it("should pass client ID as param if there is one", function (done) {
        mfa.options.client.clientId = "test";
        var requestStub = sinon.stub(mfa, "request").yields(null, { success: true });

        mfa.init(function successCb() {
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.getCalls()[0].args[0].url).to.equal("http://server.com/rps/v2/clientSettings?cid=test");
            done();
        }, function errorCb(err) {});
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
        expect(callback.getCalls()[0].args[0].name).to.equal("RequestError");
        expect(callback.getCalls()[0].args[1]).to.be.null;
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
        expect(callback.getCalls()[0].args[0].name).to.equal("RequestError");
        expect(callback.getCalls()[0].args[0].message).to.equal("The request was aborted");
        expect(callback.getCalls()[0].args[1]).to.be.null;
    });
});
