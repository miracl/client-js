import { afterEach, before, beforeEach, describe, it } from "mocha";
import Client from "../src/client.js";
import { expect } from "chai";
import sinon from "sinon";
import testConfig from "./config.js";

describe("Client sendVerificationEmail", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should fail w/o userId", (done) => {
        client.sendVerificationEmail("", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            expect(data).to.be.null;
            done();
        });
    });

    it("should return error when verification request fails", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.sendVerificationEmail("test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Verification fail");
            expect(data).to.be.null;
            done();
        });
    });

    it("should return error when verification request fails with backoff error", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { error: "REQUEST_BACKOFF" });

        client.sendVerificationEmail("test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request backoff");
            expect(data).to.deep.equal({ error: "REQUEST_BACKOFF" });
            done();
        });
    });

    it("should call success callback when verification request succeeds", (done) => {
        sinon.stub(client.http, "request").yields(null, { success: true });

        client.sendVerificationEmail("test@example.com", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client getActivationToken", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should fail w/o userId", (done) => {
        client.getActivationToken("http://example.com/verification/confirmation?code=test", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail w/o code", (done) => {
        client.getActivationToken("http://example.com/verification/confirmation?user_id=test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty verification code");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail when the request fails", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), null);

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Get activation token fail");
            expect(data).to.be.null;
            done();
        });
    });

    it("should fail when the verification fails", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { error: "UNSUCCESSFUL_VERIFICATION" });

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Unsuccessful verification");
            expect(data).to.deep.equal({ error: "UNSUCCESSFUL_VERIFICATION" });
            done();
        });
    });

    it("should invoke the callback data containing the activation token if request succeeds", (done) => {
        sinon.stub(client.http, "request").yields(null, { actToken: "testActToken" });

        client.getActivationToken("http://example.com/verification/confirmation?code=test&user_id=test@example.com", (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            expect(data.actToken).to.equal("testActToken");
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client _createMPinID", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should return error, when register request fail", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request error"), { status: 400 });

        client._createMPinID("test@example.com", null, { publicKey: "00" }, (err, data) => {
            expect(err).to.exist;
            expect(data).to.deep.equal({ status: 400 });
            done();
        });
    });

    it("should store started user", (done) => {
        sinon.stub(client.http, "request").yields(null, { projectId: "projectID" });

        client._createMPinID("test@example.com", null, { publicKey: "00" }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ projectId: "projectID" });
            expect(client.users.exists("test@example.com")).to.be.true;
            expect(client.users.get("test@example.com", "state")).to.equal("STARTED");
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client _getDeviceName", () => {
    let client;

    it("should return default device name", () => {
        client = new Client(testConfig());
        expect(client._getDeviceName()).to.equal("Browser");
    });

    it("should return provided device name", () => {
        const config = testConfig();
        config.deviceName = "test";
        client = new Client(config);
        expect(client._getDeviceName()).to.equal("test");
    });
});

describe("Client _getSecret", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should return error, when signature request fails", (done) => {
        sinon.stub(client.http, "request").yields(new Error("Request failed"), null);

        client._getSecret("secretUrl", (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Request failed");
            expect(data).to.be.null;
            done();
        });
    });

    it("should retry if the request was aborted", (done) => {
        const requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(null, { secret: true });

        client._getSecret("secretUrl", (err, data) => {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.be.null;
            expect(data).to.deep.equal({ secret: true });
            done();
        });
    });

    it("should return error if the retried request fails", (done) => {
        const requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(new Error("Request failed"), null);

        client._getSecret("secretUrl", (err, data) => {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("Request failed");
            expect(data).to.be.null;
            done();
        });
    });

    it("should return error if the retried request is aborted", (done) => {
        const requestStub = sinon.stub(client.http, "request");

        requestStub.onFirstCall().yields(new Error("The request was aborted"), null);
        requestStub.onSecondCall().yields(new Error("The request was aborted"), null);

        client._getSecret("secretUrl", (err, data) => {
            expect(requestStub.calledTwice).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("The request was aborted");
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client.http.request.restore && client.http.request.restore();
    });
});

describe("Client _createIdentity", () => {
    let client;

    beforeEach(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "0f",
            state: "REGISTERED"
        });
    });

    it("should call addShares with CS share 1 and 2", (done) => {
        const addSharesStub = sinon.stub(client.crypto, "addShares");
        sinon.stub(client.crypto, "extractPin");

        const keypair = { privateKey: "privateKey" };
        const share1 = { dvsClientSecret: "clientSecretValue1" };
        const share2 = { dvsClientSecret: "clientSecretValue2" };

        client._createIdentity("test@example.com", "1234", {}, share1, share2, keypair, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            expect(addSharesStub.calledOnce).to.be.true;
            expect(addSharesStub.firstCall.args[0]).to.equal("privateKey");
            expect(addSharesStub.firstCall.args[1]).to.equal("clientSecretValue1");
            expect(addSharesStub.firstCall.args[2]).to.equal("clientSecretValue2");
            done();
        });
    });

    it("should call extractPin with mpinId, PIN", (done) => {
        const addSharesStub = sinon.stub(client.crypto, "addShares");
        const extractPinStub = sinon.stub(client.crypto, "extractPin");

        client._createIdentity("test@example.com", "1234", { mpinId: "0f" }, {}, {}, { publicKey: "0f" }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            expect(addSharesStub.calledOnce).to.be.true;
            expect(extractPinStub.calledOnce).to.be.true;
            expect(extractPinStub.firstCall.args[0]).to.equal("0f");
            expect(extractPinStub.firstCall.args[1]).to.equal("0f");
            expect(extractPinStub.firstCall.args[2]).to.equal("1234");
            done();
        }, () => {
            throw new Error();
        });
    });

    it("should call callback with error when addShares fails", (done) => {
        const addSharesStub = sinon.stub(client.crypto, "addShares").throws(new Error("Cryptography error"));

        client._createIdentity("test@example.com", "1234", {}, {}, {}, {}, (err, data) => {
            expect(addSharesStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err.message).to.equal("Cryptography error");
            expect(data).to.be.null;
            done();
        });
    });

    it("should call callback with error when extractPin fails", (done) => {
        const thrownError = new Error;
        sinon.stub(client.crypto, "addShares");
        const extractPinStub = sinon.stub(client.crypto, "extractPin").throws(thrownError);

        client._createIdentity("test@example.com", "1234", {}, {}, {}, {}, (err, data) => {
            expect(extractPinStub.calledOnce).to.be.true;
            expect(err).to.exist;
            expect(err).to.equal(thrownError);
            expect(data).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client.crypto.extractPin.restore && client.crypto.extractPin.restore();
        client.crypto.addShares.restore && client.crypto.addShares.restore();
    });
});

describe("Client register", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
    });

    it("should return error w/o userId", () => {
        client.register("", null, () => {}, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            expect(data).to.be.null;
        });
    });

    it("should return error w/o activation token", () => {
        client.register("test@example.com", null, () => {}, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty activation token");
            expect(data).to.be.null;
        });
    });

    it("should go through the registration flow", (done) => {
        const registrationStub = sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        const getSecretStub = sinon.stub(client, "_getSecret").yields(null);
        const createIdentityStub = sinon.stub(client, "_createIdentity").yields(null, { identityData: true });

        client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ identityData: true });
            expect(registrationStub.calledOnce).to.be.true;
            expect(getSecretStub.calledTwice).to.be.true;
            expect(createIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fire callback with error on error with first _getSecret", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(new Error("Request error"));

        client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should fire callback with error on error with second _getSecret", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        const getSecretStub = sinon.stub(client, "_getSecret");
        getSecretStub.onFirstCall().yields(null);
        getSecretStub.onSecondCall().yields(new Error("Request error"));

        client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should fire callback with error on error with _createMPinID", (done) => {
        sinon.stub(client, "_createMPinID").yields(new Error("Request error"), null);

        client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.exist;
            expect(data).to.be.null;
            done();
        });
    });

    it("should fire successful callback, when _createMPinID passed successful", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 4, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, {});

        client.register("test@example.com", "activationToken", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.exist;
            done();
        });
    });

    it("should fire callback with error when registration code is not valid", (done) => {
        sinon.stub(client, "_createMPinID").yields(new Error("Request failed"), { status: 403, error: "INVALID_ACTIVATION_TOKEN" });

        client.register("test@example.com", "123456", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Invalid activation token");
            expect(data).to.be.null;
            done();
        });
    });

    it("should stop registration for different project", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { projectId: "anotherProjectID" });

        client.register("test@example.com", "123456", (passPin) => {
            passPin("1234");
        }, (err, data) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Project mismatch");
            expect(data).to.be.null;
            expect(client.users.exists("test@example.com")).to.be.false;
            done();
        });
    });

    it("should pass provided PIN length to the PIN callback", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { pinLength: 5, projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, { identity: true });

        client.register("test@example.com", "activationToken", (passPin, pinLength) => {
            expect(pinLength).to.equal(5);
            passPin("1234");
        }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ identity: true });
            done();
        });
    });

    it("should pass default PIN length to the PIN callback", (done) => {
        sinon.stub(client, "_createMPinID").yields(null, { projectId: "projectID", secretUrls: ["http://example.com/secret1", "http://example.com/secret2"] });
        sinon.stub(client, "_getSecret").yields(null);
        sinon.stub(client, "_createIdentity").yields(null, { identity: true });

        client.register("test@example.com", "activationToken", (passPin, pinLength) => {
            expect(pinLength).to.equal(4);
            passPin("1234");
        }, (err, data) => {
            expect(err).to.be.null;
            expect(data).to.deep.equal({ identity: true });
            done();
        });
    });

    afterEach(() => {
        client._createMPinID.restore && client._createMPinID.restore();
        client._getSecret.restore && client._getSecret.restore();
        client._createIdentity.restore && client._createIdentity.restore();
        client.users.remove("test@example.com");
    });
});
