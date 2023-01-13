import Client from "../src/client.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Client sign", function () {
    var client;

    before(function () {
        client = new Client(testData.init());
    });

    it("should return U and V", function (done) {
        sinon.stub(client._crypto().MPIN, "CLIENT").returns(0);
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
        sinon.stub(client._crypto().MPIN, "CLIENT").returns(-1);

        client.sign("test@example.com", "1234", "message", "timestamp", function (err, result) {
            expect(err).to.exist;
            expect(err.name).to.equal("CryptoError");
            done();
        });
    });

    afterEach(function () {
        client._crypto().MPIN.CLIENT.restore();
    });
});
