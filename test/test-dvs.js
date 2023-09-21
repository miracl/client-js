import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client sign", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            publicKey: "00",
            state: "REGISTERED"
        });
    });

    it("should return U and V", function (done) {
        sinon.stub(client, "_authentication").yields(null, true);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.be.null;
            expect(result.u).to.equal("");
            expect(result.v).to.equal("");
            done();
        });
    });

    it("should fail when authentication fails", function (done) {
        sinon.stub(client, "_authentication").yields(new Error("Authentication failed", { cause: new Error("Authentication error") }), null);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.exist;
            expect(err.message).to.equal("Signing fail");
            expect(err.cause.message).to.equal("Authentication error");
            done();
        });
    });

    it("should fail on crypto failure", function (done) {
        sinon.stub(client, "_authentication").yields(null, true);
        sinon.stub(client.crypto, "sign").throws(new Error("Cryptography error"));

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.exist;
            expect(err.message).to.equal("Signing fail");
            expect(err.cause.message).to.equal("Cryptography error");
            done();
        });
    });

    afterEach(function () {
        client._authentication.restore && client._authentication.restore();
        client.crypto.sign.restore && client.crypto.sign.restore();
    });
});
