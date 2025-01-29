import Client from "../src/client.js";
import pkg from "../package.json" with { type: "json" };
import sinon from "sinon";
import { expect } from "chai";

describe("Client", function() {
    it("should throw Error w/o options", function () {
        expect(function () {
            var client = new Client();
        }).to.throw("Invalid configuration");
    });

    it("should throw Error w/o project ID", function () {
        expect(function () {
            var config = testData.init();
            delete config["projectId"];
            var client = new Client(config);
        }).to.throw("Empty project ID");
    });

    it("should throw Error w/o user storage", function () {
        expect(function () {
            var config = testData.init();
            delete config["userStorage"];
            var client = new Client(config);
        }).to.throw("Invalid user storage");
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

    it("should set clientName", function () {
        var client = new Client(testData.init());
        expect(client.options.clientName).to.equal("MIRACL Client.js/" + pkg.version);
    });

    it("should set clientName with application info", function () {
        var config = testData.init();
        config.applicationInfo = "Test Application";
        var client = new Client(config);
        expect(client.options.clientName).to.equal("MIRACL Client.js/" + pkg.version + " Test Application");
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
        var requestStub = sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(data).to.deep.equal(sessionInfo);
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(client.http, "request").yields(new Error("Error"), null);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should store session info", function () {
        var requestStub = sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(client.session).to.deep.equal(sessionInfo);
        });
    });

    it("should set the access ID", function () {
        var requestStub = sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", function (err, data) {
            expect(client.session.accessId).to.equal("accessID");
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client fetchStatus", function() {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should make a request for session status", function () {
        var requestStub = sinon.stub(client.http, "request").yields(null, { status: "new" });

        client.fetchStatus(function (err, data) {
            expect(data.status).to.equal("new");
        });
    });

    it("should fail when request fails", function () {
        var requestStub = sinon.stub(client.http, "request").yields(new Error("Error"), null);

        client.fetchStatus(function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client sendPushNotificationForAuth", function () {
    var client;

    before(function () {
        const config = testData.init();
        config.oidc = {
            client_id: "testClientID"
        };
        client = new Client(config);
    });

    it("should make a request to the pushauth endpoint", function () {
        var requestStub = sinon.stub(client.http, "request").yields(null, { webOTT: "test" });

        client.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(data).to.exist;
            expect(requestStub.firstCall.args[0].url).to.equal("http://server.com/pushauth?client_id=testClientID");
            expect(data.webOTT).to.equal("test");
        });
    });

    it("should fail when the request fails", function () {
        var requestStub = sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(err).to.exist;
        });
    });

    it("should fail when the request fails", function () {
        var requestStub = sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400, error: "NO_PUSH_TOKEN" });

        client.sendPushNotificationForAuth("test@example.com", function (err, data) {
            expect(err).to.exist;
            expect(err.message).to.equal("No push token");
        });
    });

    it("should return an error without an user ID", function () {
        client.sendPushNotificationForAuth(null, function (err, data) {
            expect(err).to.exist;
        });
    });

    afterEach(function() {
        client.http.request.restore && client.http.request.restore();
    });
});
