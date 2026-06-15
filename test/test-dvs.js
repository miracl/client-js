import { afterEach, before, describe, it } from "mocha";
import Client from "../src/client.js";
import { expect } from "chai";
import sinon from "sinon";
import testConfig from "./config.js";

describe("Client sign", () => {
    let client;

    before(() => {
        client = new Client(testConfig());
        client.users.write("test@example.com", {
            mpinId: "exampleMpinId",
            publicKey: "00",
            state: "REGISTERED"
        });
    });

    it("should fail w/o user ID", (done) => {
        client.sign("", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty user ID");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail w/o message", (done) => {
        client.sign("test@example.com", "1234", "", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty message");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail for missing user", (done) => {
        client.sign("missing@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("User not found");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail when user doesn't have a publid key", (done) => {
        client.users.write("nopublickey@example.com", {
            mpinId: "exampleMpinId",
            state: "REGISTERED"
        });

        client.sign("nopublickey@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Empty public key");
            expect(result).to.be.null;
            done();
        });
    });

    it("should return U and V", (done) => {
        sinon.stub(client, "_authentication").yields(null, true);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.be.null;
            expect(result.u).to.equal("");
            expect(result.v).to.equal("");
            done();
        });
    });

    it("should fail when authentication fails", (done) => {
        sinon.stub(client, "_authentication").yields(new Error("Authentication fail", { cause: new Error("Request error") }), null);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Signing fail");
            expect(err.cause.message).to.equal("Request error");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail on unsuccessful authentication", (done) => {
        sinon.stub(client, "_authentication").yields(new Error("Unsuccessful authentication"), null);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Unsuccessful authentication");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail on revoked MPIN ID", (done) => {
        sinon.stub(client, "_authentication").yields(new Error("Revoked"), null);
        sinon.stub(client.crypto, "sign").returns({U: "", V: ""});

        client.sign("test@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Revoked");
            expect(result).to.be.null;
            done();
        });
    });

    it("should fail on crypto failure", (done) => {
        sinon.stub(client, "_authentication").yields(null, true);
        sinon.stub(client.crypto, "sign").throws(new Error("Cryptography error"));

        client.sign("test@example.com", "1234", "message", "timestamp", (err, result) => {
            expect(err).to.exist;
            expect(err.message).to.equal("Signing fail");
            expect(err.cause.message).to.equal("Cryptography error");
            expect(result).to.be.null;
            done();
        });
    });

    afterEach(() => {
        client._authentication.restore && client._authentication.restore();
        client.crypto.sign.restore && client.crypto.sign.restore();
    });
});
