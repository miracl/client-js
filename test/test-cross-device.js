import { afterEach, before, describe, it } from "mocha";
import Client from "../src/client.js";
import { expect } from "chai";
import sinon from "sinon";
import testConfig from "./config.js";

describe("Client createCrossDeviceSession", () => {
    let client, sessionInfo;

    before(() => {
        client = new Client(testConfig());

        sessionInfo = {
            webOTT: "token",
            qrURL: "https://example.com#accessID",
            accessId: "accessID",
            expireTime: 1790752588
        };
    });

    it("should create a session for authentication", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession(null, null, null, (err, data) => {
            expect(data).to.deep.equal({
                projectId: "projectID",
                userId: null,
                token: "token",
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: null,
                signingHash: null,
                expireTime: 1790752588
            });
        });
    });

    it("should create a session with user ID", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession("test@example.com", null, null, (err, data) => {
            expect(data).to.deep.equal({
                projectId: "projectID",
                userId: "test@example.com",
                token: "token",
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: null,
                signingHash: null,
                expireTime: 1790752588
            });
        });
    });

    it("should create a session with description", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession(null, "description", null, (err, data) => {
            expect(data).to.deep.equal({
                projectId: "projectID",
                userId: null,
                token: "token",
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: "description",
                signingHash: null,
                expireTime: 1790752588
            });
        });
    });

    it("should create a session with user ID and description", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession("test@example.com", "description", null, (err, data) => {
            expect(data).to.deep.equal({
                projectId: "projectID",
                userId: "test@example.com",
                token: "token",
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: "description",
                signingHash: null,
                expireTime: 1790752588
            });
        });
    });

    it("should create a session for signing", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession("test@example.com", "description", "0f", (err, data) => {
            expect(data).to.deep.equal({
                projectId: "projectID",
                userId: "test@example.com",
                token: "token",
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: "description",
                signingHash: "0f",
                expireTime: 1790752588
            });
        });
    });

    it("should fail when signing session is created without user ID", () => {
        sinon.stub(client.http, "request").yields(null, sessionInfo);

        client.createCrossDeviceSession(null, "description", "0f", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Session for signing must be created with user ID");
            expect(data).to.be.null;
        });
    });

    it("should fail when request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.createCrossDeviceSession("test@example.com", "description", null, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client checkCrossDeviceSessionStatus", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should make a request for new session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "new" });

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(data.status).to.equal("new");
            expect(data.userId).to.be.null;
            expect(data.jwt).to.be.null;
            expect(data.signature).to.be.null;
        });
    });

    it("should make a request for authenticated session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "authenticated", userId: "test@example.com", jwt: "jwt" });

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(data.status).to.equal("authenticated");
            expect(data.userId).to.equal("test@example.com");
            expect(data.jwt).to.equal("jwt");
            expect(data.signature).to.be.null;
        });
    });

    it("should make a request for signed session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "signed", userId: "test@example.com", signature: "signature" });

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(data.status).to.equal("signed");
            expect(data.userId).to.equal("test@example.com");
            expect(data.jwt).to.be.null;
            expect(data.signature).to.equal("signature");
        });
    });

    it("should make a request for expired session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "expired" });

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(data.status).to.equal("expired");
            expect(data.userId).to.be.null;
            expect(data.jwt).to.be.null;
            expect(data.signature).to.be.null;
        });
    });

    it("should make a request for aborted session status", () => {
        sinon.stub(client.http, "request").yields(null, { status: "abort" });

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(data.status).to.equal("abort");
            expect(data.userId).to.be.null;
            expect(data.jwt).to.be.null;
            expect(data.signature).to.be.null;
        });
    });

    it("should return error when there is no token", () => {
        client.checkCrossDeviceSessionStatus({}, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid cross-device session");
            expect(data).to.be.null;
        });
    });

    it("should fail when request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.checkCrossDeviceSessionStatus({ token: "token" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client sendPushNotification", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should make a request to the pushauth endpoint", () => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { backoff: 1 });

        client.sendPushNotification({ userId: "test@example.com", sessionId: "session" }, (err, data) => {
            expect(data).to.exist;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/push");
            expect(data.backoff).to.equal(1);
        });
    });

    it("should fail when the request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client.sendPushNotification({ userId: "test@example.com", sessionId: "session" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request error");
            expect(data).to.be.null;
        });
    });

    it("should fail when the request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400, error: "NO_PUSH_TOKEN" });

        client.sendPushNotification({ userId: "test@example.com", sessionId: "session" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("No push token");
            expect(data).to.be.null;
        });
    });

    it("should return an error without an user ID", () => {
        client.sendPushNotification({ sessionId: "session" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Cross device session created without user ID");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});
