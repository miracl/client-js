import CTX from "@miracl/crypto-js";

var CryptoContexts = {};

export default function Crypto(seed) {
    var self = this,
        entropyBytes;

    // Initialize RNG
    self.rng = new (self._crypto().RAND)();
    self.rng.clean();

    // Seed the RNG
    entropyBytes = self._hexToBytes(seed);
    self.rng.seed(entropyBytes.length, entropyBytes);
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

        // Modify MPIN settings
        CryptoContexts[curve].MPIN.PBLEN = 20;
        CryptoContexts[curve].MPIN.TRAP = 2000;
    }

    return CryptoContexts[curve];
};

Crypto.prototype.generateKeypair = function (curve) {
    var self = this,
        privateKeyBytes = [],
        publicKeyBytes = [],
        errorCode;

    errorCode = self._crypto(curve).MPIN.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
    if (errorCode != 0) {
        throw new Error("Could not generate key pair: " + errorCode);
    }

    return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
};

/**
 * Add two points on the curve that are originally in hex format
 * This function is used to add client secret shares.
 * Returns a hex encoded sum of the shares
 * @private
 */
Crypto.prototype.addShares = function (privateKeyHex, share1Hex, share2Hex, curve) {
    var self = this,
        privateKeyBytes = [],
        share1Bytes = [],
        share2Bytes = [],
        clientSecretBytes = [],
        errorCode;

    privateKeyBytes = self._hexToBytes(privateKeyHex);
    share1Bytes = self._hexToBytes(share1Hex);
    share2Bytes = self._hexToBytes(share2Hex);

    errorCode = self._crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, clientSecretBytes);
    if (errorCode !== 0) {
        throw new Error("Could not combine the client secret shares: " + errorCode);
    }

    errorCode = self._crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
    if (errorCode != 0) {
        throw new Error("Could not combine private key with client secret: " + errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

/**
 * Calculates the MPin Token
 * This function maps the M-Pin ID to a point on the curve,
 * multiplies this value by PIN and then subtractsit from
 * the client secret curve point to generate the M-Pin token.
 * Returns a hex encoded M-Pin Token
 * @private
 */
Crypto.prototype.extractPin = function (mpinId, publicKey, PIN, clientSecretHex, curve) {
    var self = this,
        clientSecretBytes = [],
        mpinIdBytes = [],
        errorCode;

    clientSecretBytes = self._hexToBytes(clientSecretHex);
    mpinIdBytes = self._hexToBytes(self._mpinIdWithPublicKey(mpinId, publicKey));

    errorCode = self._crypto(curve).MPIN.EXTRACT_PIN(self._crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
    if (errorCode !== 0) {
        throw new Error("Could not extract PIN from client secret: " + errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

Crypto.prototype.calculatePass1 = function (curve, mpinId, publicKey, token, userPin, X, SEC) {
    var self = this,
        mpinIdHex,
        errorCode,
        U = [],
        UT = [];

    mpinIdHex = self._mpinIdWithPublicKey(mpinId, publicKey);

    errorCode = self._crypto(curve).MPIN.CLIENT_1(
        self._crypto(curve).MPIN.SHA256,
        0,
        self._hexToBytes(mpinIdHex),
        self.rng,
        X,
        userPin,
        self._hexToBytes(token),
        SEC,
        U,
        UT,
        self._hexToBytes(0)
    );

    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 1 request data: " + errorCode);
    }

    return {
        UT: self._bytesToHex(UT),
        U: self._bytesToHex(U)
    };
};

Crypto.prototype.calculatePass2 = function (curve, X, yHex, SEC) {
    var self = this,
        errorCode;

    errorCode = self._crypto(curve).MPIN.CLIENT_2(X, self._hexToBytes(yHex), SEC);

    if (errorCode !== 0) {
        throw new Error("Could not calculate pass 2 request data: " + errorCode);
    }

    return self._bytesToHex(SEC);
};

Crypto.prototype.sign = function (curve, mpinId, publicKey, token, userPin, message, timestamp) {
    var self = this,
        mpinIdHex,
        errorCode,
        SEC = [],
        X = [],
        Y1 = [],
        U = [];

    mpinIdHex = self._mpinIdWithPublicKey(mpinId, publicKey);

    errorCode = self._crypto(curve).MPIN.CLIENT(
        self._crypto(curve).MPIN.SHA256,
        0,
        self._hexToBytes(mpinIdHex),
        self.rng,
        X,
        userPin,
        self._hexToBytes(token),
        SEC,
        U,
        null,
        null,
        timestamp,
        Y1,
        self._hexToBytes(message)
    );

    if (errorCode != 0) {
        throw new Error("Could not sign message: " + errorCode);
    }

    return {
        U: self._bytesToHex(U),
        V: self._bytesToHex(SEC)
    };
};

/**
 * Returns the public key bytes appended to the MPin ID bytes in hex encoding
 * @private
 */
Crypto.prototype._mpinIdWithPublicKey = function (mpinId, publicKey) {
    var self = this,
        mpinIdBytes = self._hexToBytes(mpinId),
        publicKeyBytes = self._hexToBytes(publicKey),
        i;

    if (!mpinIdBytes) {
        return;
    }

    if (!publicKeyBytes) {
        return mpinId;
    }

    for (i = 0; i < publicKeyBytes.length; i++) {
        mpinIdBytes.push(publicKeyBytes[i]);
    }

    return self._bytesToHex(mpinIdBytes);
};

Crypto.prototype._hexToBytes = function (hexValue) {
    var len, byteValue, i;

    if (!hexValue) {
        return;
    }

    len = hexValue.length;
    byteValue = [];

    for (i = 0; i < len; i += 2) {
        byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
    }

    return byteValue;
};

Crypto.prototype._bytesToHex = function (b) {
    var s = "",
        len = b.length,
        ch, i;

    for (i = 0; i < len; i++) {
        ch = b[i];
        s += ((ch >>> 4) & 15).toString(16);
        s += (ch & 15).toString(16);
    }

    return s;
};
