import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client", function() {
    it("should throw Error w/o options", function () {
        expect(function () {
            var client = new Client();
        }).to.throw("Missing options");
    });

    it("should throw Error w/o project ID", function () {
        expect(function () {
            var config = testData.init();
            delete config["projectId"];
            var client = new Client(config);
        }).to.throw("Missing project ID");
    });

    it("should throw Error w/o user storage", function () {
        expect(function () {
            var config = testData.init();
            delete config["userStorage"];
            var client = new Client(config);
        }).to.throw("Missing user storage object");
    });

    it("should return client instance", function () {
        var client = new Client(testData.init());
        expect(client).to.be.an.instanceof(Client);
    });

    it("should set default server address if there is none", function () {
        var config = testData.init();
        delete config["server"];
        var client = new Client(config);
        expect(client.options.server).to.equal("https://api.mpin.io");
    });

    it("should set default PIN length to 4 if there is none", function () {
        var config = testData.init();
        delete config["defaultPinLength"];
        var client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if less than 4", function () {
        var config = testData.init();
        config.defaultPinLength = 3;
        var client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if more than 6", function () {
        var config = testData.init();
        config.defaultPinLength = 7;
        var client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to provided value within range", function () {
        var config = testData.init();
        config.defaultPinLength = 5;
        var client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(5);
    });
});

describe("Client setAccessId", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should set access id", function () {
        client.setAccessId("test");
        expect(client.session.accessId).to.equal("test");
    });
});

describe("Client fetchAccessId", function () {
    var client, sessionInfo;

    before(function () {
        client = new Client(testData.init());

        sessionInfo = {
            webOTT: 1,
            accessURL: "https://example.com/access",
            qrURL: "https://example.com#accessID",
            accessId: "accessID",
        };
    });

    it("should make a request for access ID", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(data).to.deep.equal(sessionInfo);
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(client, "_request").yields(new Error("Error"), null);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should fail if response doesn't have all session data", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, {});

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should store session info", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(client.session).to.deep.equal(sessionInfo);
        });
    });

    it("should set the access ID", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(client.session.accessId).to.equal("accessID");
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client fetchStatus", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should make a request for session status", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, { status: "new" });

        client.fetchStatus(function (err, data) {
            expect(data.status).to.equal("new");
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(client, "_request").yields(new Error("Error"), null);

        client.fetchStatus(function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should fail if response doesn't have expected data", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, {});

        client.fetchStatus(function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client sendPushNotificationForAuth", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should make a request to the pushauth endpoint", function () {
        var requestStub = sinon.stub(client, "_request").yields(null, { webOTT: "test" });

        client.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(data).to.exist;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/pushauth?client_id=testClientID");
            expect(data.webOTT).to.equal("test");
        });
    });

    it("should fail when the request fails", function () {
        var requestStub = sinon.stub(client, "_request").yields(new Error("Error"), null);

        client.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should return an error without an user ID", function () {
        client.sendPushNotificationForAuth(null, function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        client._request.restore && client._request.restore();
    });
});

describe("Client request", function() {
    var client, server, requests = [];

    before(function () {
        client = new Client(testData.init());

        var xhr = global.XMLHttpRequest = sinon.useFakeXMLHttpRequest();
        xhr.onCreate = function (xhr) {
            requests.push(xhr);
        };
    });

    it("should throw error missing callback", function () {
        expect(function () {
            client._request({ url: "reqUrl" });
        }).to.throw("Bad or missing callback");

        expect(function () {
            client._request({ url: "reqUrl" }, "string");
        }).to.throw("Bad or missing callback");
    });

    it("should throw error missing URL", function () {
        expect(function () {
            client._request({}, function () {});
        }).to.throw("Missing URL for request");
    });

    it("should handle successful JSON response", function () {
        requests = [];

        var callback = sinon.spy();
        client._request({
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
        client._request({
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
        client._request({
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
        client._request({
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
        client._request({
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
        client._request({
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

    it("should set project ID header", function () {
        requests = [];

        client._request({
            url: "/test-project-id-header",
        }, function () {});

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("X-MIRACL-CID");
        expect(requests[0].requestHeaders["X-MIRACL-CID"]).to.equal("projectID");
    });

    it("should set client version header", function () {
        requests = [];

        client._request({
            url: "/test-client-version-header",
        }, function () {});

        var expectedVersion = "MIRACL Client.js/" + process.env.npm_package_version;

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("X-MIRACL-CLIENT");
        expect(requests[0].requestHeaders["X-MIRACL-CLIENT"]).to.equal(expectedVersion);
    });

    it("should set extended client version header", function () {
        requests = [];

        var extendedVersion = "extended client version";

        var config = testData.init()
        config.applicationInfo = extendedVersion;

        client = new Client(config);

        client._request({
            url: "/test-client-version-header",
        }, function () {});

        var expectedVersion = "MIRACL Client.js/" + process.env.npm_package_version + " " + extendedVersion;

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("X-MIRACL-CLIENT");
        expect(requests[0].requestHeaders["X-MIRACL-CLIENT"]).to.equal(expectedVersion);
    });
});
