import CTX from "@miracl/crypto-js";

const CryptoContexts = {};

export default class Crypto {
    constructor(seed) {
        // Initialize RNG
        this.rng = new (this._crypto().RAND)();
        this.rng.clean();

        // Seed the RNG
        const entropyBytes = hexToBytes(seed);
        this.rng.seed(entropyBytes.length, entropyBytes);
    }

    _crypto(curve) {
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
    }

    generateKeypair(curve) {
        const privateKeyBytes = [];
        const publicKeyBytes = [];

        const errorCode = this._crypto(curve).MPIN.GET_DVS_KEYPAIR(this.rng, privateKeyBytes, publicKeyBytes);
        if (errorCode !== 0) {
            throw new Error("Could not generate key pair: " + errorCode);
        }

        return { publicKey: bytesToHex(publicKeyBytes), privateKey: bytesToHex(privateKeyBytes) };
    }

    /**
     * Add two points on the curve that are originally in hex format
     * This function is used to add Client Secret shares.
     * Returns a hex-encoded sum of the shares
     * @private
     */
    addShares(privateKeyHex, share1Hex, share2Hex, curve) {
        const privateKeyBytes = hexToBytes(privateKeyHex);
        const share1Bytes = hexToBytes(share1Hex);
        const share2Bytes = hexToBytes(share2Hex);
        const clientSecretBytes = [];

        const errorCodeRecombine = this._crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, clientSecretBytes);
        if (errorCodeRecombine !== 0) {
            throw new Error("Could not combine the client secret shares: " + errorCodeRecombine);
        }

        const errorCodeG1 = this._crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
        if (errorCodeG1 !== 0) {
            throw new Error("Could not combine private key with client secret: " + errorCodeG1);
        }

        return bytesToHex(clientSecretBytes);
    }

    /**
     * Calculates the M-PIN Token
     * This function maps the M-PIN ID to a point on the curve,
     * multiplies this value by PIN and then subtracts it from
     * the Client Secret curve point to generate the M-PIN token.
     * Returns a hex-encoded M-PIN Token
     * @private
     */
    extractPin(mpinId, publicKey, PIN, clientSecretHex, curve) {
        const clientSecretBytes = hexToBytes(clientSecretHex);
        const mpinIdBytes = hexToBytes(this._mpinIdWithPublicKey(mpinId, publicKey));

        const errorCode = this._crypto(curve).MPIN.EXTRACT_PIN(this._crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
        if (errorCode !== 0) {
            throw new Error("Could not extract PIN from client secret: " + errorCode);
        }

        return bytesToHex(clientSecretBytes);
    }

    calculatePass1(mpinId, publicKey, token, userPin, X, SEC, curve) {
        const U = [], UT = [];

        const mpinIdHex = this._mpinIdWithPublicKey(mpinId, publicKey);

        const errorCode = this._crypto(curve).MPIN.CLIENT_1(
            this._crypto(curve).MPIN.SHA256,
            0,
            hexToBytes(mpinIdHex),
            this.rng,
            X,
            userPin,
            hexToBytes(token),
            SEC,
            U,
            UT,
            hexToBytes(0)
        );

        if (errorCode !== 0) {
            throw new Error("Could not calculate pass 1 request data: " + errorCode);
        }

        return {
            UT: bytesToHex(UT),
            U: bytesToHex(U)
        };
    }

    calculatePass2(X, yHex, SEC, curve) {
        const errorCode = this._crypto(curve).MPIN.CLIENT_2(X, hexToBytes(yHex), SEC);
        if (errorCode !== 0) {
            throw new Error("Could not calculate pass 2 request data: " + errorCode);
        }

        return bytesToHex(SEC);
    }

    sign(mpinId, publicKey, token, userPin, message, timestamp, curve) {
        const SEC = [];
        const X = [];
        const Y1 = [];
        const U = [];

        const mpinIdHex = this._mpinIdWithPublicKey(mpinId, publicKey);

        const errorCode = this._crypto(curve).MPIN.CLIENT(
            this._crypto(curve).MPIN.SHA256,
            0,
            hexToBytes(mpinIdHex),
            this.rng,
            X,
            userPin,
            hexToBytes(token),
            SEC,
            U,
            null,
            null,
            timestamp,
            Y1,
            hexToBytes(message)
        );

        if (errorCode !== 0) {
            throw new Error("Could not sign message: " + errorCode);
        }

        return {
            U: bytesToHex(U),
            V: bytesToHex(SEC)
        };
    }

    randomString(len) {
        const byteArr = new Array(len);
        for (let i = 0; i < len; ++i) {
            byteArr[i] = this.rng.getByte();
        }

        return bytesToHex(byteArr);
    }

    /**
     * Returns the public key bytes appended to the M-PIN ID bytes in hex encoding
     * @private
     */
    _mpinIdWithPublicKey(mpinId, publicKey) {
        const mpinIdBytes = hexToBytes(mpinId);
        const publicKeyBytes = hexToBytes(publicKey);

        if (!mpinIdBytes) {
            return;
        }

        if (!publicKeyBytes) {
            return mpinId;
        }

        for (let i = 0; i < publicKeyBytes.length; i++) {
            mpinIdBytes.push(publicKeyBytes[i]);
        }

        return bytesToHex(mpinIdBytes);
    }
}

function hexToBytes(hexValue) {
    if (!hexValue) {
        return;
    }

    const byteValue = [];

    for (let i = 0; i < hexValue.length; i += 2) {
        byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
    }

    return byteValue;
}

function bytesToHex(b) {
    let s = "";

    for (let i = 0; i < b.length; i++) {
        const ch = b[i];
        s += ((ch >>> 4) & 15).toString(16);
        s += (ch & 15).toString(16);
    }

    return s;
}
