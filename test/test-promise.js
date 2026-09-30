import { afterEach, before, describe, it } from "mocha";
import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import Client from "../src/promise.js";
import sinon from "sinon";
import testConfig from "./config.js";

use(chaiAsPromised);

describe("Promises", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should call fetchAccessId", async () => {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        await expect(client.fetchAccessId("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on fetchAccessId error", async () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        await expect(client.fetchAccessId("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call fetchStatus", async () => {
        sinon.stub(client.http, "request").yields(null, { status: "new" });

        await expect(client.fetchStatus()).to.eventually.deep.equal({ status: "new" });
    });

    it("should fail on fetchStatus error", async () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        await expect(client.fetchStatus()).to.be.rejectedWith(err);
    });

    it("should call sendPushNotificationForAuth", async () => {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        await expect(client.sendPushNotificationForAuth("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on sendPushNotificationForAuth error", async () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        await expect(client.sendPushNotificationForAuth("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call sendVerificationEmail", async () => {
        sinon.stub(client.http, "request").yields(null, { backoff: 1 });

        await expect(client.sendVerificationEmail("test@example.com")).to.eventually.deep.equal({ backoff: 1 });
    });

    it("should fail on sendVerificationEmail error", async () => {
        const reqErr = new Error("Request error");
        sinon.stub(client.http, "request").yields(reqErr, null);

        try {
            await client.sendVerificationEmail("test@example.com");
            expect.fail("Expected sendVerificationEmail to reject");
        } catch (err) {
            expect(err.message).to.equal("Verification fail");
            expect(err.cause).to.equal(reqErr);
        }
    });

    it("should call getActivationToken", async () => {
        sinon.stub(client.http, "request").yields(null, { actToken: "test" });

        await expect(client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.eventually.deep.equal({ userId: "test@example.com", actToken: "test" });
    });

    it("should fail on getActivationToken error", async () => {
        const reqErr = new Error("Request error");
        sinon.stub(client.http, "request").yields(reqErr, null);

        try {
            await client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test");
            expect.fail("Expected getActivationToken to reject");
        } catch (err) {
            expect(err.message).to.equal("Get activation token fail");
            expect(err.cause).to.equal(reqErr);
        }

    });

    it("should call register", async () => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getTAShares").yields(null, [{ share: 1 }, { share: 2 }]);
        sinon.stub(client, "_createIdentity").yields(null, { state: "REGISTERED" });

        await expect(client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        })).to.eventually.deep.equal({ state: "REGISTERED" });

        client._createMPinID.restore();
        client._getTAShares.restore();
        client._createIdentity.restore();
    });

    it("should fail on register error", async () => {
        const createMPinIDErr = new Error("Create MPinID error");
        sinon.stub(client, "_createMPinID").yields(createMPinIDErr, null);

        try {
            await client.register("test@example.com", "activationToken", (passPin) => {
                passPin("1234");
            });
            expect.fail("Expected register to reject");
        } catch (err) {
            expect(err.message).to.equal("Registration fail");
            expect(err.cause).to.equal(createMPinIDErr);
        }

        client._createMPinID.restore();
    });

    it("should call authenticate", async () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        await expect(client.authenticate("test@example.com", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticate error", async () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        await expect(client.authenticate("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithQRCode", async () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        await expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithQRCode error", async () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        await expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithAppLink", async () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        await expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithAppLink error", async () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        await expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithNotificationPayload", async () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        await expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithNotificationPayload error", async () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        await expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.be.rejectedWith(err);
    });

    it("should call generateQuickCode", async () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });

        await expect(client.generateQuickCode("test@example.com", "1234")).to.eventually.deep.equal({ code: "123456", OTP: "123456", ttlSeconds: 60, expireTime: 1737520575 });
    });

    it("should fail on generateQuickCode error", async () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        await expect(client.generateQuickCode("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call sign", async () => {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            dtas: "dtas",
            publicKey: "00",
            state: "REGISTERED"
        });

        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.crypto, "sign").returns({U: "1", V: "2"});

        await expect(client.sign("test@example.com", "1234", "0f", "timestamp")).to.eventually.deep.equal({
            dtas: "dtas",
            hash: "0f",
            mpinId: "exampleMpinId",
            publicKey: "00",
            u: "1",
            v: "2"
        });

        client.crypto.sign.restore();
    });

    it("should fail on sign error", async () => {
        await expect(client.sign("test@example.com", "1234", "0f", "timestamp")).to.be.rejectedWith("Signing fail");
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client._authentication.restore && client._authentication.restore();
    });
});
