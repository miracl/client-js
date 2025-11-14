import Client from "../src/promise.js";
import sinon from "sinon";
import { expect } from "chai";
import testConfig from "./config.js";

describe("Promises", function() {
    var client;

    before(function () {
        client = new Client(testConfig());
    });

    it("should call fetchAccessId", async function () {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });
        expect(await client.fetchAccessId("test@example.com")).to.deep.equal({ accessId: "accessID" });
    });

    it("should fail on fetchAccessId error", async function () {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        try {
            await client.fetchAccessId("test@example.com");
        } catch (err) {
            expect(err.message).to.equal("Request error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call fetchStatus", async function () {
        sinon.stub(client.http, "request").yields(null, { status: "new" });
        expect(await client.fetchStatus()).to.deep.equal({ status: "new" });
    });

    it("should fail on fetchStatus error", async function () {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        try {
            await client.fetchStatus();
        } catch (err) {
            expect(err.message).to.equal("Request error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call sendPushNotificationForAuth", async function () {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });
        expect(await client.sendPushNotificationForAuth("test@example.com")).to.deep.equal({ accessId: "accessID" });
    });

    it("should fail on sendPushNotificationForAuth error", async function () {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        try {
            await client.sendPushNotificationForAuth("test@example.com")
        } catch (err) {
            expect(err.message).to.equal("Request error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call sendVerificationEmail", async function () {
        sinon.stub(client.http, "request").yields(null, { backoff: 1 });
        expect(await client.sendVerificationEmail("test@example.com")).to.deep.equal({ backoff: 1 });
    });

    it("should fail on sendVerificationEmail error", async function () {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        try {
            await client.sendVerificationEmail("test@example.com")
        } catch (err) {
            expect(err.message).to.equal("Verification fail");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call getActivationToken", async function () {
        sinon.stub(client.http, "request").yields(null, { actToken: "test" });
        expect(await client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.deep.equal({ userId: "test@example.com", actToken: "test" });
    });

    it("should fail on getActivationToken error", async function () {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        try {
            await client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")
        } catch (err) {
            expect(err.message).to.equal("Get activation token fail");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call register", async function () {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, { state: "REGISTERED" });

        expect(await client.register("test@example.com", "activationToken", function (passPin) { passPin("1234"); })).to.deep.equal({ state: "REGISTERED" });

        client._createMPinID.restore();
        client._getSecret.restore();
        client._createIdentity.restore();
    });

    it("should fail on register error", async function () {
        sinon.stub(client, "_createMPinID").yields(new Error("Request error"), null);

        try {
            await client.register("test@example.com", "activationToken", function (passPin) { passPin("1234"); })
        } catch (err) {
            expect(err.message).to.equal("Registration fail");
            return;
        }

        client._createMPinID.restore();

        throw new Error("Unexpected result");
    });

    it("should call authenticate", async function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        expect(await client.authenticate("test@example.com", "1234")).to.deep.equal({ message: "OK" });
    });

    it("should fail on authenticate error", async function () {
        sinon.stub(client, "_authentication").yields(new Error("Authentication error"), null);

        try {
            await client.authenticate("test@example.com", "1234")
        } catch (err) {
            expect(err.message).to.equal("Authentication error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call authenticateWithQRCode", async function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        expect(await client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithQRCode error", async function () {
        sinon.stub(client, "_authentication").yields(new Error("Authentication error"), null);

        try {
            await client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")
        } catch (err) {
            expect(err.message).to.equal("Authentication error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call authenticateWithAppLink", async function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        expect(await client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithAppLink error", async function () {
        sinon.stub(client, "_authentication").yields(new Error("Authentication error"), null);

        try {
            await client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")
        } catch (err) {
            expect(err.message).to.equal("Authentication error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call authenticateWithNotificationPayload", async function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        expect(await client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithNotificationPayload error", async function () {
        sinon.stub(client, "_authentication").yields(new Error("Authentication error"), null);

        try {
            await client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")
        } catch (err) {
            expect(err.message).to.equal("Authentication error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call generateQuickCode", async function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });
        expect(await client.generateQuickCode("test@example.com", "1234")).to.deep.equal({ code: "123456", OTP: "123456", ttlSeconds: 60, expireTime: 1737520575 });
    });

    it("should fail on generateQuickCode error", async function () {
        sinon.stub(client, "_authentication").yields(new Error("Authentication error"), null);

        try {
            await client.generateQuickCode("test@example.com", "1234")
        } catch (err) {
            expect(err.message).to.equal("Authentication error");
            return;
        }

        throw new Error("Unexpected result");
    });

    it("should call sign", async function () {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            publicKey: "00",
            state: "REGISTERED"
        });

        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.crypto, "sign").returns({U: "1", V: "2"});

        var res = await client.sign("test@example.com", "1234", "0f", "timestamp")

        expect(res.u).to.equal("1");
        expect(res.v).to.equal("2");

        client.crypto.sign.restore();
    });

    it("should fail on sign error", async function () {
        try {
            await client.sign("test@example.com", "1234", "0f", "timestamp")
        } catch (err) {
            expect(err.message).to.equal("Signing fail");
            return;
        }

        throw new Error("Unexpected result");
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client._authentication.restore && client._authentication.restore();
    });
});
