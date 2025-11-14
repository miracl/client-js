import Client from "../src/promise.js";
import sinon from "sinon";
import { expect, use } from "chai";
import chaiAsPromised from "chai-as-promised";
import testConfig from "./config.js";

use(chaiAsPromised);

describe("Promises", function() {
    var client;

    before(function () {
        client = new Client(testConfig());
    });

    it("should call fetchAccessId", function () {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        expect(client.fetchAccessId("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on fetchAccessId error", function () {
        var err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.fetchAccessId("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call fetchStatus", function () {
        sinon.stub(client.http, "request").yields(null, { status: "new" });

        expect(client.fetchStatus()).to.eventually.deep.equal({ status: "new" });
    });

    it("should fail on fetchStatus error", function () {
        var err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.fetchStatus()).to.be.rejectedWith(err);
    });

    it("should call sendPushNotificationForAuth", function () {
        sinon.stub(client.http, "request").yields(null, { accessId: "accessID" });

        expect(client.sendPushNotificationForAuth("test@example.com")).to.eventually.deep.equal({ accessId: "accessID" });
    });

    it("should fail on sendPushNotificationForAuth error", function () {
        var err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.sendPushNotificationForAuth("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call sendVerificationEmail", function () {
        sinon.stub(client.http, "request").yields(null, { backoff: 1 });

        expect(client.sendVerificationEmail("test@example.com")).to.eventually.deep.equal({ backoff: 1 });
    });

    it("should fail on sendVerificationEmail error", function () {
        var err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.sendVerificationEmail("test@example.com")).to.be.rejectedWith(err);
    });

    it("should call getActivationToken", function () {
        sinon.stub(client.http, "request").yields(null, { actToken: "test" });

        expect(client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.eventually.deep.equal({ userId: "test@example.com", actToken: "test" });
    });

    it("should fail on getActivationToken error", function () {
        var err = new Error("Request error");
        sinon.stub(client.http, "request").yields(err, null);

        expect(client.getActivationToken("https://example.com/verification/confirmation?user_id=test@example.com&code=test")).to.be.rejectedWith(err);
    });

    it("should call register", function () {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, { state: "REGISTERED" });

        expect(client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        })).to.eventually.deep.equal({ state: "REGISTERED" });

        client._createMPinID.restore();
        client._getSecret.restore();
        client._createIdentity.restore();
    });

    it("should fail on register error", function () {
        var err = new Error("Create MPinID error");
        sinon.stub(client, "_createMPinID").yields(err, null);

        expect(client.register("test@example.com", "activationToken", function (passPin) {
            passPin("1234");
        })).to.be.rejectedWith(err);

        client._createMPinID.restore();
    });

    it("should call authenticate", function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticate("test@example.com", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticate error", function () {
        var err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticate("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithQRCode", function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithQRCode error", function () {
        var err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithQRCode("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithAppLink", function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithAppLink error", function () {
        var err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithAppLink("test@example.com", "https://example.com#accessID", "1234")).to.be.rejectedWith(err);
    });

    it("should call authenticateWithNotificationPayload", function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });

        expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.eventually.deep.equal({ message: "OK" });
    });

    it("should fail on authenticateWithNotificationPayload error", function () {
        var err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.authenticateWithNotificationPayload({ userID: "test@example.com", qrURL: "https://example.com#accessID" }, "1234")).to.be.rejectedWith(err);
    });

    it("should call generateQuickCode", function () {
        sinon.stub(client, "_authentication").yields(null, { message: "OK" });
        sinon.stub(client.http, "request").yields(null, { code: "123456", ttlSeconds: 60, expireTime: 1737520575 });

        expect(client.generateQuickCode("test@example.com", "1234")).to.eventually.deep.equal({ code: "123456", OTP: "123456", ttlSeconds: 60, expireTime: 1737520575 });
    });

    it("should fail on generateQuickCode error", function () {
        var err = new Error("Authentication error");
        sinon.stub(client, "_authentication").yields(err, null);

        expect(client.generateQuickCode("test@example.com", "1234")).to.be.rejectedWith(err);
    });

    it("should call sign", function () {
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

    it("should fail on sign error", function () {
        expect(client.sign("test@example.com", "1234", "0f", "timestamp")).to.be.rejectedWith("Signing fail");
    });

    afterEach(function () {
        client.http.request.restore && client.http.request.restore();
        client._authentication.restore && client._authentication.restore();
    });
});
