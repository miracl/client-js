import Crypto from "../src/crypto.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("Crypto generateKeypair", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should return private and public key", function () {
        var keypair = crypto.generateKeypair();
        expect(keypair.privateKey).to.exist;
        expect(keypair.publicKey).to.exist;
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(crypto._crypto().MPIN, "GET_DVS_KEYPAIR").returns(-1);

        expect(function () {
            crypto.generateKeypair();
        }).to.throw("Could not generate key pair: -1");
    });

    afterEach(function () {
        crypto._crypto().MPIN.GET_DVS_KEYPAIR.restore && crypto._crypto().MPIN.GET_DVS_KEYPAIR.restore();
    });
});

describe("Crypto addShares", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should throw error on RECOMBINE_G1 failure", function () {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(-1);
        expect(function () {
            crypto.addShares("privateKey", "test", "test");
        }).to.throw("Could not combine the client secret shares: -1");
    });

    it("should throw error on GET_G1_MULTIPLE failure", function () {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(0);
        sinon.stub(crypto._crypto().MPIN, "GET_G1_MULTIPLE").returns(-1);
        expect(function () {
            crypto.addShares("privateKey", "test", "test");
        }).to.throw("Could not combine private key with client secret: -1");
    });

    it("should return combined client secret", function () {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(0);
        sinon.stub(crypto._crypto().MPIN, "GET_G1_MULTIPLE").returns(0);
        expect(crypto.addShares("privateKey", "test", "test")).to.equal("");
    });

    afterEach(function () {
        crypto._crypto().MPIN.RECOMBINE_G1.restore && crypto._crypto().MPIN.RECOMBINE_G1.restore();
        crypto._crypto().MPIN.GET_G1_MULTIPLE.restore && crypto._crypto().MPIN.GET_G1_MULTIPLE.restore();
    });
});

describe("Crypto extractPin", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should throw error on crypto failure", function () {
        sinon.stub(crypto._crypto().MPIN, "EXTRACT_PIN").returns(-1);
        expect(function () {
            crypto.extractPin("0f", "0f", "1234", "hex", "BN254CX")
        }).to.throw("Could not extract PIN from client secret: -1");
    });

    it("should return combined client secret", function () {
        sinon.stub(crypto._crypto().MPIN, "EXTRACT_PIN").returns(0);
        expect(crypto.extractPin("0f", "0f", "1234", "hex", "BN254CX")).to.equal("0000");
    });

    afterEach(function () {
        crypto._crypto().MPIN.EXTRACT_PIN.restore && crypto._crypto().MPIN.EXTRACT_PIN.restore();
    });
});

describe("Crypto calculatePass1", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should calculate pass 1", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_1").returns(0);

        crypto.calculatePass1("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_1").returns(-14);

        expect(function () {
            crypto.calculatePass1("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not calculate pass 1 request data: -14");
    });

    afterEach(function () {
        crypto._crypto().MPIN.CLIENT_1.restore && crypto._crypto().MPIN.CLIENT_1.restore();
    });
});

describe("Crypto calculatePass2", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should calculate pass 2", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_2").returns(0);

        crypto.calculatePass2("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_2").returns(-14);

        expect(function () {
            crypto.calculatePass2("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not calculate pass 2 request data: -14");
    });

    afterEach(function () {
        crypto._crypto().MPIN.CLIENT_2.restore && crypto._crypto().MPIN.CLIENT_2.restore();
    });
});

describe("Crypto sign", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should calculate signature", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT").returns(0);

        crypto.sign("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", function () {
        sinon.stub(crypto._crypto().MPIN, "CLIENT").returns(-14);

        expect(function () {
            crypto.sign("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not sign message: -14");
    });

    afterEach(function () {
        crypto._crypto().MPIN.CLIENT.restore && crypto._crypto().MPIN.CLIENT.restore();
    });
});

describe("Crypto _mpinIdWithPublicKey", function () {
    var crypto;

    before(function () {
        crypto = new Crypto("0f");
    });

    it("should combine the MPIN ID with the public key", function () {
        expect(crypto._mpinIdWithPublicKey("0f", "0f")).to.equal("0f0f");
    });

    it("should return original MPIN ID if no public key is provided", function () {
        expect(crypto._mpinIdWithPublicKey("0f")).to.equal("0f");
        expect(crypto._mpinIdWithPublicKey("0f", null)).to.equal("0f");
    });
});
