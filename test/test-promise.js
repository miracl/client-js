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

    it("should call fetchAccessId", () => {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        expect(client.fetchAccessId("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on fetchAccessId error", () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.fetchAccessId("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call fetchStatus", () => {
        sinon.stub(client.http, "request").yields(null, { status: "new" });

        expect(client.fetchStatus()).to.eventually.deep.equal({ status: "new" });
    });

    it("should fail on fetchStatus error", () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.fetchStatus()).to.be.rejectedWith(err);
    });

    it("should call sendPushNotificationForAuth", () => {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        expect(client.sendPushNotificationForAuth("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on sendPushNotificationForAuth error", () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.sendPushNotificationForAuth("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call sendVerificationEmail", () => {
        sinon.stub(client.http, "request").yields(null, { backoff: 1 });

        expect(client.sendVerificationEmail("test@example.com")).to.eventually.deep.equal({ backoff: 1 });
    });

    it("should fail on sendVerificationEmail error", () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.sendVerificationEmail("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call getActivationToken", () => {
        sinon.stub(client.http, "request").yields(null, { actToken: "test" });

        expect(client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.eventually.deep.equal({ userId: "test@example.com", actToken: "test" });
    });

    it("should fail on getActivationToken error", () => {
        const err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.be.rejectedWith(err);
    });

    it("should call register", () => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, { state: "REGISTERED" });

        expect(client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        })).to.eventually.deep.equal({ state: "REGISTERED" });

        client._createMPinID.restore();
        client._getSecret.restore();
        client._createIdentity.restore();
    });

    it("should fail on register error", () => {
        const err = new Error("Create MPinID error");
        sinon.stub(client, "_createMPinID").yields(err, null);

        expect(client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        })).to.be.rejectedWith(err);

        client._createMPinID.restore();
    });

    it("should call authenticate", () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticate("test@example.com", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticate error", () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticate("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithQRCode", () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithQRCode error", () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithAppLink", () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithAppLink error", () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithNotificationPayload", () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithNotificationPayload error", () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.be.rejectedWith(err);
    });

    it("should call generateQuickCode", () => {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });

        expect(client.generateQuickCode("test@example.com", "1234")).to.eventually.deep.equal({ code: "123456", OTP: "123456", ttlSeconds: 60, expireTime: 1737520575 });
    });

    it("should fail on generateQuickCode error", () => {
        const err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.generateQuickCode("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call sign", () => {
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            publicKey: "00",
            state: "REGISTERED"
        });

        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.crypto, "sign").returns({U: "1", V: "2"});

        expect(client.sign("test@example.com", "1234", "0f", "timestamp")).to.eventually.deep.equal({u: "1", v: "2"});

        client.crypto.sign.restore();
    });

    it("should fail on sign error", () => {
        expect(client.sign("test@example.com", "1234", "0f", "timestamp")).to.be.rejectedWith("Signing fail");
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
        client._authentication.restore && client._authentication.restore();
    });
});
