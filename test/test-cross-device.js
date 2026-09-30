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
                type: "authentication",
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
                type: "authentication",
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
                type: "authentication",
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
                type: "authentication",
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
                type: "signing",
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

describe("Client _getCrossDeviceSession", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should get session for authentication", () => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { projectId: "projectID", expireTime: 1790752588 });

        client._getCrossDeviceSession("https://example.com#accessID", (err, data) => {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/codeStatus");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            expect(requestStub.firstCall.args[0].data.status).to.equal("wid");
            expect(requestStub.firstCall.args[0].data.wid).to.equal("accessID");

            expect(data).to.deep.equal({
                type: "authentication",
                projectId: "projectID",
                userId: null,
                token: null,
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: null,
                signingHash: null,
                expireTime: 1790752588
            });
        });
    });

    it("should get session for signing", () => {
        const requestStub = sinon.stub(client.http, "request").yields(null, {
            projectId: "projectID",
            prerollId: "test@example.com",
            description: "Signing session",
            hash: "00",
            expireTime: 1790752588
        });

        client._getCrossDeviceSession("https://example.com#accessID", (err, data) => {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/codeStatus");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            expect(requestStub.firstCall.args[0].data.status).to.equal("wid");
            expect(requestStub.firstCall.args[0].data.wid).to.equal("accessID");

            expect(data).to.deep.equal({
                type: "signing",
                projectId: "projectID",
                userId: "test@example.com",
                token: null,
                url: "https://example.com#accessID",
                sessionId: "accessID",
                description: "Signing session",
                signingHash: "00",
                expireTime: 1790752588
            });
        });
    });

    it("should fail when session request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request failed"), null);

        client._getCrossDeviceSession("https://example.com#accessID", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Get cross-device session request failed");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client getCrossDeviceSessionFromQRCode", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should call _getCrossDeviceSession with scope 'jwt'", () => {
        const session = { projectId: "projectID" };
        const getCrossDeviceSessionStub = sinon.stub(client, "_getCrossDeviceSession").yields(null, session);

        client.getCrossDeviceSessionFromQRCode("https://example.com#accessID", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal(session);
            expect(getCrossDeviceSessionStub.calledOnce).to.be.true;
            expect(getCrossDeviceSessionStub.firstCall.args[0]).to.equal("https://example.com#accessID");
        });
    });

    afterEach(() => {
        client._getCrossDeviceSession.restore && client._getCrossDeviceSession.restore();
    });
});

describe("Client getCrossDeviceSessionFromLink", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should call _getCrossDeviceSession with scope 'jwt'", () => {
        const session = { projectId: "projectID" };
        const getCrossDeviceSessionStub = sinon.stub(client, "_getCrossDeviceSession").yields(null, session);

        client.getCrossDeviceSessionFromLink("https://example.com#accessID", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal(session);
            expect(getCrossDeviceSessionStub.calledOnce).to.be.true;
            expect(getCrossDeviceSessionStub.firstCall.args[0]).to.equal("https://example.com#accessID");
        });
    });

    afterEach(() => {
        client._getCrossDeviceSession.restore && client._getCrossDeviceSession.restore();
    });
});

describe("Client getCrossDeviceSessionFromNotificationPayload", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should call _getCrossDeviceSession with scope 'jwt'", () => {
        const session = { projectId: "projectID" };
        const getCrossDeviceSessionStub = sinon.stub(client, "_getCrossDeviceSession").yields(null, session);

        client.getCrossDeviceSessionFromNotificationPayload({ qrURL: "https://example.com#accessID" }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal(session);
            expect(getCrossDeviceSessionStub.calledOnce).to.be.true;
            expect(getCrossDeviceSessionStub.firstCall.args[0]).to.equal("https://example.com#accessID");
        });
    });

    it("should fail with invalid payload", () => {
        client.getCrossDeviceSessionFromNotificationPayload({}, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid push notification payload");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client._getCrossDeviceSession.restore && client._getCrossDeviceSession.restore();
    });
});

describe("Client authenticateCrossDeviceSession", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call _authentication with scope 'jwt'", () => {
        const authenticationStub = sinon.stub(client, "_authentication").yields(null, { success: true });

        client.authenticateCrossDeviceSession({ sessionId: "accessID" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(authenticationStub.firstCall.args[0]).to.equal("test@example.com");
            expect(authenticationStub.firstCall.args[1]).to.equal("1234");
            expect(authenticationStub.firstCall.args[2]).to.deep.equal(["jwt"]);
            expect(authenticationStub.firstCall.args[3]).to.equal("accessID");
        });
    });

    it("should fail when _authentication fails", () => {
        sinon.stub(client, "_authentication").yields(new Error("Authentication fail"), null);

        client.authenticateCrossDeviceSession({ sessionId: "accessID" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Authentication fail");
            expect(data).to.be.null;
        });
    });

    it("should fail when userId doesn't match session userId", () => {
        client.authenticateCrossDeviceSession({ sessionId: "accessID", userId: "another@example.com" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Cross-device session was initiated for different user ID");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
    });
});

describe("Client signCrossDeviceSession", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });
    });

    it("should call sign", () => {
        const signStub = sinon.stub(client, "sign").yields(null, { signature: "signed" });
        sinon.stub(client.http, "request").yields(null, { success: true });

        const start = Math.floor(new Date().getTime() / 1000);

        client.signCrossDeviceSession({ sessionId: "accessID", userId: "test@example.com", signingHash: "hash" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(signStub.calledOnce).to.be.true;
            expect(signStub.firstCall.args[0]).to.equal("test@example.com");
            expect(signStub.firstCall.args[1]).to.equal("1234");
            expect(signStub.firstCall.args[2]).to.deep.equal("hash");
            // Check timestamp
            expect(signStub.firstCall.args[3] >= start).to.be.true;
            expect(signStub.firstCall.args[3] < start+1).to.be.true;
        });
    });

    it("should make session update request", () => {
        sinon.stub(client, "sign").yields(null, { signature: "signed" });
        const requestStub = sinon.stub(client.http, "request").yields(null, { success: true });

        client.signCrossDeviceSession({ sessionId: "accessID", userId: "test@example.com", signingHash: "hash" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.be.null;
            expect(data.success).to.be.true;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/codeStatus");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            expect(requestStub.firstCall.args[0].data.status).to.equal("signed");
            expect(requestStub.firstCall.args[0].data.wid).to.equal("accessID");
            expect(requestStub.firstCall.args[0].data.signature).to.equal(Buffer.from(JSON.stringify({signature: "signed"})).toString("base64"));
        });
    });

    it("should fail when sign fails", () => {
        sinon.stub(client, "sign").yields(new Error("Signing fail"), null);

        client.signCrossDeviceSession({ sessionId: "accessID", userId: "test@example.com", signingHash: "hash" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Signing fail");
            expect(data).to.be.null;
        });
    });

    it("should fail when userId doesn't match session userId", () => {
        client.signCrossDeviceSession({ sessionId: "accessID", userId: "another@example.com", signingHash: "hash" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Cross-device session was initiated for different user ID");
            expect(data).to.be.null;
        });
    });

    it("should fail when cross-device session doesn't have a signing hash", () => {
        client.signCrossDeviceSession({ sessionId: "accessID", userId: "test@example.com", signingHash: null }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty message");
            expect(data).to.be.null;
        });
    });

    it("should fail when session update request fails", () => {
        sinon.stub(client, "sign").yields(null, { success: true });
        sinon.stub(client.http, "request").yields(new Error("Request failed"), null);

        client.signCrossDeviceSession({ sessionId: "accessID", userId: "test@example.com", signingHash: "hash" }, "test@example.com", "1234", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Updating cross-device session failed");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.sign.restore && client.sign.restore();
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client abortCrossDeviceSession", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should make session abort request", () => {
        const requestStub = sinon.stub(client.http, "request").yields(null, { status: "abort" });

        client.abortCrossDeviceSession({ sessionId: "accessID" }, (err, data) => {
            expect(err).to.be.null;
            expect(data.status).to.equal("abort");
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://project.miracl.io/rps/v2/codeStatus");
            expect(requestStub.firstCall.args[0].type).to.equal("POST");
            expect(requestStub.firstCall.args[0].data.status).to.equal("abort");
            expect(requestStub.firstCall.args[0].data.wid).to.equal("accessID");
        });
    });

    it("should fail when session abort request fails", () => {
        sinon.stub(client.http, "request").yields(new Error("Request failed"), null);

        client.abortCrossDeviceSession({ sessionId: "accessID" }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Aborting cross-device session failed");
            expect(data).to.be.null;
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});
