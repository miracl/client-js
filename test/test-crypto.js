import { afterEach, before, describe, it } from "mocha";
import Crypto from "../src/crypto.js";
import { expect } from "chai";
import sinon from "sinon";

describe("Crypto generateKeypair", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should return private and public key", () => {
        const keypair = crypto.generateKeypair();
        expect(keypair.privateKey).to.exist;
        expect(keypair.publicKey).to.exist;
    });

    it("should throw error on crypto failure", () => {
        sinon.stub(crypto._crypto().MPIN, "GET_DVS_KEYPAIR").returns(-1);

        expect(() => {
            crypto.generateKeypair();
        }).to.throw("Could not generate key pair: -1");
    });

    afterEach(() => {
        crypto._crypto().MPIN.GET_DVS_KEYPAIR.restore && crypto._crypto().MPIN.GET_DVS_KEYPAIR.restore();
    });
});

describe("Crypto addShares", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should throw error on RECOMBINE_G1 failure", () => {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(-1);
        expect(() => {
            crypto.addShares("privateKey", "test", "test");
        }).to.throw("Could not combine the client secret shares: -1");
    });

    it("should throw error on GET_G1_MULTIPLE failure", () => {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(0);
        sinon.stub(crypto._crypto().MPIN, "GET_G1_MULTIPLE").returns(-1);
        expect(() => {
            crypto.addShares("privateKey", "test", "test");
        }).to.throw("Could not combine private key with client secret: -1");
    });

    it("should return combined client secret", () => {
        sinon.stub(crypto._crypto().MPIN, "RECOMBINE_G1").returns(0);
        sinon.stub(crypto._crypto().MPIN, "GET_G1_MULTIPLE").returns(0);
        expect(crypto.addShares("privateKey", "test", "test")).to.equal("");
    });

    afterEach(() => {
        crypto._crypto().MPIN.RECOMBINE_G1.restore && crypto._crypto().MPIN.RECOMBINE_G1.restore();
        crypto._crypto().MPIN.GET_G1_MULTIPLE.restore && crypto._crypto().MPIN.GET_G1_MULTIPLE.restore();
    });
});

describe("Crypto extractPin", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should throw error on crypto failure", () => {
        sinon.stub(crypto._crypto().MPIN, "EXTRACT_PIN").returns(-1);
        expect(() => {
            crypto.extractPin("0f", "0f", "1234", "hex", "BN254CX");
        }).to.throw("Could not extract PIN from client secret: -1");
    });

    it("should return combined client secret", () => {
        sinon.stub(crypto._crypto().MPIN, "EXTRACT_PIN").returns(0);
        expect(crypto.extractPin("0f", "0f", "1234", "hex", "BN254CX")).to.equal("0000");
    });

    afterEach(() => {
        crypto._crypto().MPIN.EXTRACT_PIN.restore && crypto._crypto().MPIN.EXTRACT_PIN.restore();
    });
});

describe("Crypto calculatePass1", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should calculate pass 1", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_1").returns(0);

        crypto.calculatePass1("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_1").returns(-14);

        expect(() => {
            crypto.calculatePass1("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not calculate pass 1 request data: -14");
    });

    afterEach(() => {
        crypto._crypto().MPIN.CLIENT_1.restore && crypto._crypto().MPIN.CLIENT_1.restore();
    });
});

describe("Crypto calculatePass2", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should calculate pass 2", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_2").returns(0);

        crypto.calculatePass2("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT_2").returns(-14);

        expect(() => {
            crypto.calculatePass2("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not calculate pass 2 request data: -14");
    });

    afterEach(() => {
        crypto._crypto().MPIN.CLIENT_2.restore && crypto._crypto().MPIN.CLIENT_2.restore();
    });
});

describe("Crypto sign", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should calculate signature", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT").returns(0);

        crypto.sign("BN254CX", "0f", "0f", "00", "1111", [], []);
    });

    it("should throw an error when calculations fail", () => {
        sinon.stub(crypto._crypto().MPIN, "CLIENT").returns(-14);

        expect(() => {
            crypto.sign("BN254CX", "0f", "0f", "00", "1111", [], []);
        }).to.throw("Could not sign message: -14");
    });

    afterEach(() => {
        crypto._crypto().MPIN.CLIENT.restore && crypto._crypto().MPIN.CLIENT.restore();
    });
});

describe("Crypto _mpinIdWithPublicKey", () => {
    let crypto;

    before(() => {
        crypto = new Crypto("0f");
    });

    it("should combine the MPIN ID with the public key", () => {
        expect(crypto._mpinIdWithPublicKey("0f", "0f")).to.equal("0f0f");
    });

    it("should return original MPIN ID if no public key is provided", () => {
        expect(crypto._mpinIdWithPublicKey("0f")).to.equal("0f");
        expect(crypto._mpinIdWithPublicKey("0f", null)).to.equal("0f");
    });
});
