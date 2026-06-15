import { afterEach, before, describe, it } from "mocha";
import Client from "../src/client.js";
import { expect } from "chai";
import { readFileSync } from "fs";
import sinon from "sinon";
import testConfig from "./config.js";

const pkg = JSON.parse(readFileSync("./package.json"));

describe("Client", () => {
    it("should throw Error w/o options", () => {
        expect(() => {
            new Client();
        }).to.throw("Invalid configuration");
    });

    it("should throw Error w/o project ID", () => {
        const config = testConfig();
        delete config["projectId"];

        expect(() => {
            new Client(config);
        }).to.throw("Empty project ID");
    });

    it("should throw Error w/o user storage", () => {
        const config = testConfig();
        delete config["userStorage"];

        expect(() => {
            new Client(config);
        }).to.throw("Invalid user storage");
    });

    it("should return client instance", () => {
        const client = new Client(testConfig());
        expect(client).to.be.an.instanceof(Client);
    });

    it("should set default server address if there is no projectUrl", () => {
        const config = testConfig();
        delete config["projectUrl"];
        const client = new Client(config);
        expect(client.options.projectUrl).to.equal("https://api.mpin.io");
    });

    it("should set default PIN length to 4 if there is none", () => {
        const config = testConfig();
        delete config["defaultPinLength"];
        const client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if less than 4", () => {
        const config = testConfig();
        config.defaultPinLength = 3;
        const client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to 4 if more than 6", () => {
        const config = testConfig();
        config.defaultPinLength = 7;
        const client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(4);
    });

    it("should set default PIN length to provided value within range", () => {
        const config = testConfig();
        config.defaultPinLength = 5;
        const client = new Client(config);
        expect(client.options.defaultPinLength).to.equal(5);
    });

    it("should set clientName", () => {
        const client = new Client(testConfig());
        expect(client.options.clientName).to.equal("MIRACL Client.js/" + pkg.version);
    });

    it("should set clientName with application info", () => {
        const config = testConfig();
        config.applicationInfo = "Test Application";
        const client = new Client(config);
        expect(client.options.clientName).to.equal("MIRACL Client.js/" + pkg.version + " Test Application");
    });
});

describe("Client setAccessId", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should set access id", () => {
        client.setAccessId("test");
        expect(client.session.accessId).to.equal("test");
    });
});

describe("Client fetchAccessId", () => {
    let client, sessionInfo;

    before(() => {
        client = new Client(testConfig());

        sessionInfo = {
            webOTT: 1,
            accessURL: "https://example.com/access",
            qrURL: "https://example.com#accessID",
            accessId: "accessID",
        };
    });

    it("should make a request for access ID", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", (err, data) => {
            expect(data).to.deep.equal(sessionInfo);
        });
    });

    it("should fail when request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Error"), null);

        client.fetchAccessId("test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
        });
    });

    it("should store session info", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal(sessionInfo);
            expect(client.session).to.deep.equal(sessionInfo);
        });
    });

    it("should set the access ID", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.fetchAccessId("test@example.com", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal(sessionInfo);
            expect(client.session.accessId).to.equal("accessID");
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client fetchStatus", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should make a request for session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "new" });

        client.fetchStatus((err, data) => {
            expect(data.status).to.equal("new");
        });
    });

    it("should fail when request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Error"), null);

        client.fetchStatus((err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client sendPushNotificationForAuth", () => {
    let client;

    before(() => {
        const config = testConfig();
        config.oidc = {
            client_id: "testClientID" // eslint-disable-line camelcase
        };
        client = new Client(config);
    });

    it("should make a request to the pushauth endpoint", () => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { webOTT: "test" });

        client.sendPushNotificationForAuth("test@example.com", (err, data) => {
            expect(data).to.exist;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/pushauth?client_id=testClientID");
            expect(data.webOTT).to.equal("test");
        });
    });

    it("should fail when the request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client.sendPushNotificationForAuth("test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
        });
    });

    it("should fail when the request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400, error: "NO_PUSH_TOKEN" });

        client.sendPushNotificationForAuth("test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("No push token");
            expect(data).to.be.null;
        });
    });

    it("should return an error without an user ID", () => {
        client.sendPushNotificationForAuth(null, (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});
