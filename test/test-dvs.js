import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client signingRegister", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should go through the DVS registration flow", function (done) {
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, true);
        var renewDvsSecretStub = sinon.stub(client, "_renewDvsSecret").yields(null, true);

        client.signingRegister("test@example.com", "1234", "1234", function (err, result) {
            expect(err).to.be.null;
            expect(authenticationStub.calledOnce).to.be.true;
            expect(renewDvsSecretStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should fail if authentication fails", function (done) {
        sinon.stub(client, "_authentication").yields({ error: true });

        client.signingRegister("test@example.com", "1234", "1234", function (err, result) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
        client._renewDvsSecret.restore && client._renewDvsSecret.restore();
    });

});

describe("Client _renewDvsSecret", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should create a signing identity", function (done) {
        var getDvsSecret1Stub = sinon.stub(client, "_getDvsSecret1").yields(null, true);
        var getSecret2Stub = sinon.stub(client, "_getSecret2").yields(null, true);
        var createSigningIdentityStub = sinon.stub(client, "_createSigningIdentity").yields(null, true);

        client._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.be.null;
            expect(getDvsSecret1Stub.calledOnce).to.be.true;
            expect(getSecret2Stub.calledOnce).to.be.true;
            expect(createSigningIdentityStub.calledOnce).to.be.true;
            done();
        });
    });

    it("should return error if _getDvsSecret1 fails", function (done) {
        sinon.stub(client, "_init").yields(null, true);
        sinon.stub(client, "_getDvsSecret1").yields({ error: true });

        client._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if _getSecret2 fails", function (done) {
        sinon.stub(client, "_init").yields(null,true);
        sinon.stub(client, "_getDvsSecret1").yields(null, true);
        sinon.stub(client, "_getSecret2").yields({ error: true }, null);

        client._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    it("should return error if createSigningIdentity fails", function (done) {
        sinon.stub(client, "_init").yields(true);
        sinon.stub(client, "_getDvsSecret1").yields(null, true);
        sinon.stub(client, "_getSecret2").yields(null, true);
        sinon.stub(client, "_createSigningIdentity").yields({ error: true });

        client._renewDvsSecret("test@example.com", "1234", { token: "token", curve: "BN254CX" }, function (err) {
            expect(err).to.exist;
            expect(err.error).to.be.true;
            done();
        });
    });

    afterEach(function () {
        client._init.restore && client._init.restore();
        client._getDvsSecret1.restore && client._getDvsSecret1.restore();
        client._getSecret2.restore && client._getSecret2.restore();
        client._createSigningIdentity.restore && client._createSigningIdentity.restore();
    })
});

describe("Client _getDvsSecret1", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.clientSettings = testData.settings();
    });

    it("should call error callback when request fails", function (done) {
        sinon.stub(client, "request").yields({}, null);

        client._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, data) {
            expect(err).to.exist;
            done();
        });
    });

    it("should call success callback with data", function (done) {
        sinon.stub(client, "request").yields(null, { success: true });

        client._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err, cs1Data) {
            expect(err).to.be.null;
            expect(cs1Data).to.exist;
            expect(cs1Data).to.have.property("success");
            expect(cs1Data.success).to.be.true;
            done();
        });
    });

    it("should make request to dvs register endpoint", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });

        client._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].url).to.equal("https://api.miracl.net/dvs/register");
            done();
        });
    });

    it("should make request with public key and device name", function (done) {
        var requestStub = sinon.stub(client, "request").yields(null, { success: true });
        sinon.stub(client, "_getDeviceName").returns("device");

        client._getDvsSecret1({ publicKey: "public" }, "dvsRegisterToken", function (err) {
            expect(err).to.be.null;
            expect(requestStub.calledOnce).to.be.true;
            expect(requestStub.firstCall.args[0].data).to.deep.equal({ publicKey: "public", deviceName: "device", dvsRegisterToken: "dvsRegisterToken" });
            done();
        });
    });

    afterEach(function () {
        client.request.restore && client.request.restore();
    });
});

describe("Client _generateSignKeypair", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return private and public key", function () {
        var keypair = client._generateSignKeypair();
        expect(keypair.privateKey).to.exist;
        expect(keypair.publicKey).to.exist;
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(client.crypto().MPIN, "GET_DVS_KEYPAIR").returns(-1);

        expect(function () {
            client._generateSignKeypair();
        }).to.throw("CryptoError");

        client.crypto().MPIN.GET_DVS_KEYPAIR.restore();
    });
});

describe("Client _generateSignClientSecret", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return the modified client secret", function () {
        sinon.stub(client.crypto().MPIN, "GET_G1_MULTIPLE").returns(0);

        expect(client._generateSignClientSecret("privateKey", "0f")).to.equal("0f");

        client.crypto().MPIN.GET_G1_MULTIPLE.restore();
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(client.crypto().MPIN, "GET_G1_MULTIPLE").returns(-1);

        expect(function () {
            client._generateSignClientSecret("privateKey", "secret");
        }).to.throw("CryptoError");

        client.crypto().MPIN.GET_G1_MULTIPLE.restore();
    });
});

describe("Client _getSignMpinId", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should combine the MPIN ID with the public key", function () {
        expect(client._getSignMpinId("0f", "0f")).to.equal("0f0f");
    });
});

describe("Client _createSigningIdentity", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should create identity ready for signing", function (done) {
        sinon.stub(client, "_addShares").returns("secret");
        sinon.stub(client, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(client, "_getSignMpinId").returns("signMpinId");
        sinon.stub(client, "_extractPin").returns("token");

        client._createSigningIdentity(
            "test@example.com",
            "1234",
            {
                mpinId: "dvsMpinId",
                dtas: "dtas",
                dvsClientSecretShare: "share1Hex",
                curve: "BN254CX"
            },
            {
                dvsClientSecret: "share2Hex"
            },
            {
                privateKey: "private",
                publicKey: "public"
            }, function (err, data) {
                expect(err).to.be.null;
                expect(client.dvsUsers.get("test@example.com", "mpinId")).to.equal("dvsMpinId");
                expect(client.dvsUsers.get("test@example.com", "publicKey")).to.equal("public");
                expect(client.dvsUsers.get("test@example.com", "token")).to.equal("token");
                expect(client.dvsUsers.get("test@example.com", "state")).to.equal("REGISTERED");
                done();
            }
        );
    });

    it("should invoke callback with error if addShares fails", function (done) {
        sinon.stub(client, "_addShares").throws(new Error);
        sinon.stub(client, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(client, "_getSignMpinId").returns("signMpinId");
        sinon.stub(client, "_extractPin").returns("token");

        client._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if generateSignClientSecret fails", function (done) {
        sinon.stub(client, "_addShares").returns("secret");
        sinon.stub(client, "_generateSignClientSecret").throws(new Error);
        sinon.stub(client, "_getSignMpinId").returns("signMpinId");
        sinon.stub(client, "_extractPin").returns("token");

        client._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if getSignMpinId fails", function (done) {
        sinon.stub(client, "_addShares").returns("secret");
        sinon.stub(client, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(client, "_getSignMpinId").throws(new Error);
        sinon.stub(client, "_extractPin").returns("token");

        client._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    it("should invoke callback with error if extractPin fails", function (done) {
        sinon.stub(client, "_addShares").returns("secret");
        sinon.stub(client, "_generateSignClientSecret").returns("signSecret");
        sinon.stub(client, "_getSignMpinId").returns("signMpinId");
        sinon.stub(client, "_extractPin").throws(new Error);

        client._createSigningIdentity("test@example.com", "1234", {}, {}, {}, function (err) {
            expect(err).to.exist;
            done();
        });
    });

    afterEach(function () {
        client._addShares.restore && client._addShares.restore();
        client._generateSignClientSecret.restore && client._generateSignClientSecret.restore();
        client._getSignMpinId.restore && client._getSignMpinId.restore();
        client._extractPin.restore && client._extractPin.restore();
    })
});

describe("Client sign", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return U and V", function (done) {
        sinon.stub(client.crypto().MPIN, "CLIENT").returns(0);
        var authenticationStub = sinon.stub(client, "_authentication").yields(null, true);

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.be.null;
            expect(result.u).to.equal("");
            expect(result.v).to.equal("");
            done();
        });

        client._authentication.restore && client._authentication.restore();
    });

    it("should throw error on crypto failure", function (done) {
        sinon.stub(client.crypto().MPIN, "CLIENT").returns(-1);

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    afterEach(function () {
        client.crypto().MPIN.CLIENT.restore();
    });
});
