import CTX from "@miracl/crypto-js";

const CryptoContexts = {};

export default function Crypto(seed) {
    // Initialize RNG
    this.rng = new (this._crypto().RAND)();
    this.rng.clean();

    // Seed the RNG
    const entropyBytes = this._hexToBytes(seed);
    this.rng.seed(entropyBytes.length, entropyBytes);
}

Crypto.prototype._crypto = function (curve) {
    // Set to default curve if not provided
    if (!curve) {
        curve = "BN254CX";
    }

    if (!CryptoContexts[curve]) {
        // Create a new curve context
        CryptoContexts[curve] = new CTX(curve);

        // Change maximum PIN length to 6 digits
        CryptoContexts[curve].MPIN.MAXPIN = 1000000;

        // Modify M-PIN settings
        CryptoContexts[curve].MPIN.PBLEN = 20;
        CryptoContexts[curve].MPIN.TRAP = 2000;
    }

    return CryptoContexts[curve];
};

Crypto.prototype.generateKeypair = function (curve) {
    const privateKeyBytes = [];
    const publicKeyBytes = [];

    const errorCode = this._crypto(curve).MPIN.GET_DVS_KEYPAIR(this.rng, privateKeyBytes, publicKeyBytes);
    if (errorCode !== 0) {
        throw new Error("Could not generate key pair: " + errorCode);
    }

    return { publicKey: this._bytesToHex(publicKeyBytes), privateKey: this._bytesToHex(privateKeyBytes) };
};

/**
 * Add two points on the curve that are originally in hex format
 * This function is used to add Client Secret shares.
 * Returns a hex-encoded sum of the shares
 * @private
 */
Crypto.prototype.addShares = function (privateKeyHex, share1Hex, share2Hex, curve) {
    const privateKeyBytes = this._hexToBytes(privateKeyHex);
    const share1Bytes = this._hexToBytes(share1Hex);
    const share2Bytes = this._hexToBytes(share2Hex);
    const clientSecretBytes = [];

    const errorCodeRecombine = this._crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, clientSecretBytes);
    if (errorCodeRecombine !== 0) {
        throw new Error("Could not combine the client secret shares: " + errorCodeRecombine);
    }

    const errorCodeG1 = this._crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
    if (errorCodeG1 !== 0) {
        throw new Error("Could not combine private key with client secret: " + errorCodeG1);
    }

    return this._bytesToHex(clientSecretBytes);
};

/**
 * Calculates the M-PIN Token
 * This function maps the M-PIN ID to a point on the curve,
 * multiplies this value by PIN and then subtracts it from
 * the Client Secret curve point to generate the M-PIN token.
 * Returns a hex-encoded M-PIN Token
 * @private
 */
Crypto.prototype.extractPin = function (mpinId, publicKey, PIN, clientSecretHex, curve) {
    const clientSecretBytes = this._hexToBytes(clientSecretHex);
    const mpinIdBytes = this._hexToBytes(this._mpinIdWithPublicKey(mpinId, publicKey));

    const errorCode = this._crypto(curve).MPIN.EXTRACT_PIN(this._crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
    if (errorCode !== 0) {
        throw new Error("Could not extract PIN from client secret: " + errorCode);
    }

    return this._bytesToHex(clientSecretBytes);
};

Crypto.prototype.calculatePass1 = function (curve, mpinId, publicKey, token, userPin, X, SEC) {
    const U = [], UT = [];

    const mpinIdHex = this._mpinIdWithPublicKey(mpinId, publicKey);

    const errorCode = this._crypto(curve).MPIN.CLIENT_1(
        this._crypto(curve).MPIN.SHA256,
        0,
        this._hexToBytes(mpinIdHex),
        this.rng,
        X,
        userPin,
        this._hexToBytes(token),
        SEC,
        U,
        UT,
        this._hexToBytes(0)
    );

    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 1 request data: " + errorCode);
    }

    return {
        UT: this._bytesToHex(UT),
        U: this._bytesToHex(U)
    };
};

Crypto.prototype.calculatePass2 = function (curve, X, yHex, SEC) {
    const errorCode = this._crypto(curve).MPIN.CLIENT_2(X, this._hexToBytes(yHex), SEC);
    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 2 request data: " + errorCode);
    }

    return this._bytesToHex(SEC);
};

Crypto.prototype.sign = function (curve, mpinId, publicKey, token, userPin, message, timestamp) {
    const SEC = [];
    const X = [];
    const Y1 = [];
    const U = [];

    const mpinIdHex = this._mpinIdWithPublicKey(mpinId, publicKey);

    const errorCode = this._crypto(curve).MPIN.CLIENT(
        this._crypto(curve).MPIN.SHA256,
        0,
        this._hexToBytes(mpinIdHex),
        this.rng,
        X,
        userPin,
        this._hexToBytes(token),
        SEC,
        U,
        null,
        null,
        timestamp,
        Y1,
        this._hexToBytes(message)
    );

    if (errorCode !== 0) {
        throw new Error("Could not sign message: " + errorCode);
    }

    return {
        U: this._bytesToHex(U),
        V: this._bytesToHex(SEC)
    };
};

/**
 * Returns the public key bytes appended to the M-PIN ID bytes in hex encoding
 * @private
 */
Crypto.prototype._mpinIdWithPublicKey = function (mpinId, publicKey) {
    const mpinIdBytes = this._hexToBytes(mpinId);
    const publicKeyBytes = this._hexToBytes(publicKey);

    if (!mpinIdBytes) {
        return;
    }

    if (!publicKeyBytes) {
        return mpinId;
    }

    for (let i = 0; i < publicKeyBytes.length; i++) {
        mpinIdBytes.push(publicKeyBytes[i]);
    }

    return this._bytesToHex(mpinIdBytes);
};

Crypto.prototype._hexToBytes = function (hexValue) {
    if (!hexValue) {
        return;
    }

    const byteValue = [];

    for (let i = 0; i < hexValue.length; i += 2) {
        byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
    }

    return byteValue;
};

Crypto.prototype._bytesToHex = function (b) {
    let s = "";

    for (let i = 0; i < b.length; i++) {
        const ch = b[i];
        s += ((ch >>> 4) & 15).toString(16);
        s += (ch & 15).toString(16);
    }

    return s;
};
