import Crypto from "./crypto.js";
import HTTP from "./http.js";
import Users from "./users.js";

/**
 * @class
 * @param {Object} options
 * @param {string} options.projectUrl - MIRACL Trust Project URL used for communication with the MIRACL Trust API
 * @param {string} options.projectId - MIRACL Trust Project ID
 * @param {string} options.seed - Hex-encoded random number generator seed
 * @param {string} options.deviceName - Name of the current device
 * @param {Object} options.userStorage - Storage for saving user data
 * @param {Object} options.oidc - Parameters for initializing an OIDC auth session
 * @param {string} options.oidc.client_id - OIDC Client ID
 * @param {string} options.oidc.redirect_uri - OIDC redirect URI
 * @param {string} options.oidc.response_type - OIDC response type. Only 'code' is supported
 * @param {string} options.oidc.scope - OIDC scope. Must include 'openid'
 * @param {string} options.oidc.state - OIDC state
 * @param {bool}   options.cors - Enable CORS requests if set to 'true'
 * @param {number} options.requestTimeout - Time before an HTTP request times out in milliseconds
 * @param {string} options.applicationInfo - Set additional information that will be sent via X-MIRACL-CLIENT HTTP header
 */
export default function Client(options) {
    if (!options) {
        throw new Error("Invalid configuration");
    }

    if (!options.projectId) {
        throw new Error("Empty project ID");
    }

    if (!options.userStorage) {
        throw new Error("Invalid user storage");
    }

    if (!options.projectUrl) {
        options.projectUrl = "https://api.mpin.io";
    } else {
        // Remove trailing slash from URL, if there is one
        options.projectUrl = options.projectUrl.replace(/\/$/, "");
    }

    // Ensure the default PIN length is between 4 and 6
    if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
        options.defaultPinLength = 4;
    }

    if (!options.requestTimeout || isNaN(options.requestTimeout)) {
        options.requestTimeout = 4000;
    }

    if (!options.oidc) {
        options.oidc = {};
    }

    // Set the client name using the current lib version and provided application info
    options.clientName = "MIRACL Client.js/8.8.0" + (options.applicationInfo ? " " + options.applicationInfo : "");

    this.options = options;

    this.http = new HTTP(options.requestTimeout, options.clientName, options.projectId, options.cors);

    this.crypto = new Crypto(options.seed);

    this.users = new Users(options.userStorage, options.projectId, "mfa");
}

Client.prototype.options = {};

Client.prototype.session = {};

/**
 * Set the access/session ID
 *
 * @param {string} accessId
 */
Client.prototype.setAccessId = function (accessId) {
    this.session.accessId = accessId;
};

/**
 * Make a request to start a new session and fetch the access/session ID
 *
 * @param {string} userId - The unique identifier of the user that will be authenticating (not required)
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchAccessId = function (userId, callback) {
    const reqData = {
        url: this.options.projectUrl + "/rps/v2/session",
        type: "POST",
        data: {
            projectId: this.options.projectId,
            userId: userId
        }
    };

    this.http.request(reqData, (error, res) => {
        if (error) {
            return callback(error, null);
        }

        this.session = res;

        callback(null, res);
    });
};

/**
 * Get session status
 *
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchStatus = function (callback) {
    const reqData = {
        url: this.options.projectUrl + "/rps/v2/access",
        type: "POST",
        data: {
            webOTT: this.session.webOTT
        }
    };

    this.http.request(reqData, (error, data) => {
        if (error) {
            return callback(error, null);
        }

        callback(null, data);
    });
};

/**
 * Start the push authentication flow
 *
 * @param {string} userId - The unique identifier of the user that will be authenticating
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendPushNotificationForAuth = function (userId, callback) {
    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    const reqData = {
        url: this.options.projectUrl + "/pushauth?" + this._urlEncode(this.options.oidc),
        type: "POST",
        data: {
            prerollId: userId
        }
    };

    this.http.request(reqData, (err, result) => {
        if (err) {
            if (result && result.error === "NO_PUSH_TOKEN") {
                return callback(new Error("No push token", { cause: err }), null);
            }

            return callback(err, null);
        }

        this.session.webOTT = result.webOTT;

        callback(null, result);
    });
};

/**
 * Start the verification process for a specified User ID (must be an email address)
 *
 * @param {string} userId - The email address for which to start verification
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendVerificationEmail = function (userId, callback) {
    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    const reqData = {
        url: this.options.projectUrl + "/verification/email",
        type: "POST",
        data: {
            userId: userId,
            mpinId: this.users.get(userId, "mpinId"),
            projectId: this.options.projectId,
            accessId: this.session.accessId,
            deviceName: this._getDeviceName(),
            clientId: this.options.oidc["client_id"],
            redirectURI: this.options.oidc["redirect_uri"],
            scope: this.options.oidc["scope"] ? this.options.oidc["scope"].split(" ") : [],
            state: this.options.oidc["state"],
            nonce: this.options.oidc["nonce"]
        }
    };

    this.http.request(reqData, (err, result) => {
        if (err) {
            if (result && result.error === "REQUEST_BACKOFF") {
                return callback(new Error("Request backoff", { cause: err }), result);
            }

            return callback(new Error("Verification fail", { cause: err }), result);
        }

        callback(null, result);
    });
};

/**
 * Finish the verification process
 *
 * @param {string} verificationURI - The URI received in the email containing the verification code
 * @param {function(Error, Object)} callback
 */
Client.prototype.getActivationToken = function (verificationURI, callback) {
    const params = this._parseUriParams(verificationURI);

    if (!params["user_id"]) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!params["code"]) {
        return callback(new Error("Empty verification code"), null);
    }

    const reqData = {
        url: this.options.projectUrl + "/verification/confirmation",
        type: "POST",
        data: {
            userId: params["user_id"],
            code: params["code"]
        }
    };

    this.http.request(reqData, (err, result) => {
        if (err) {
            if (result && result.error === "UNSUCCESSFUL_VERIFICATION") {
                return callback(new Error("Unsuccessful verification", { cause: err }), result);
            }

            return callback(new Error("Get activation token fail", { cause: err }), result);
        }

        result.userId = params["user_id"];
        callback(null, result);
    });
};

/**
 * Create an identity for the specified User ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} activationToken - The code received from the verification process
 * @param {function} pinCallback - Called when the PIN code needs to be entered
 * @param {function(Error, Object)} callback
 */
Client.prototype.register = function (userId, activationToken, pinCallback, callback) {
    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!activationToken) {
        return callback(new Error("Empty activation token"), null);
    }

    const keypair = this.crypto.generateKeypair("BN254CX");

    this._createMPinID(userId, activationToken, keypair, (err, identityData) => {
        if (err) {
            if (identityData && identityData.error === "INVALID_ACTIVATION_TOKEN") {
                return callback(new Error("Invalid activation token", { cause: err }), null);
            }

            return callback(new Error("Registration fail", { cause: err }), null);
        }

        if (identityData.projectId !== this.options.projectId) {
            return callback(new Error("Project mismatch"), null);
        }

        this._getSecret(identityData.secretUrls[0], (err, sec1Data) => {
            if (err) {
                return callback(new Error("Registration fail", { cause: err }), null);
            }

            this._getSecret(identityData.secretUrls[1], (err, sec2Data) => {
                if (err) {
                    return callback(new Error("Registration fail", { cause: err }), null);
                }

                let pinLength = identityData.pinLength;
                if (!pinLength) {
                    pinLength = this.options.defaultPinLength;
                }

                // Should be called to continue the flow after a PIN was provided
                const passPin = (userPin) => {
                    this._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
                };

                pinCallback(passPin, pinLength);
            });
        });
    });
};

Client.prototype._createMPinID = function (userId, activationToken, keypair, callback) {
    const regData = {
        url: this.options.projectUrl + "/registration",
        type: "POST",
        data: {
            userId: userId,
            deviceName: this._getDeviceName(),
            activationToken: activationToken,
            publicKey: keypair.publicKey
        }
    };

    this.http.request(regData, (err, result) => {
        if (err) {
            return callback(err, result);
        }

        this.users.write(userId, { state: this.users.states.start });

        callback(null, result);
    });
};

Client.prototype._getDeviceName = function () {
    if (this.options.deviceName) {
        return this.options.deviceName;
    }

    return "Browser";
};

Client.prototype._getSecret = function (secretUrl, callback) {
    const requestData = {
        url: secretUrl
    };

    this.http.request(requestData, (err, result) => {
        if (err) {
            if (err.message === "The request was aborted") {
                this.http.request(requestData, callback);
            } else {
                callback(err, result);
            }

            return;
        }

        callback(null, result);
    });
};

Client.prototype._createIdentity = function (userId, userPin, identityData, sec1Data, sec2Data, keypair, callback) {
    let csHex, token;

    try {
        csHex = this.crypto.addShares(keypair.privateKey, sec1Data.dvsClientSecret, sec2Data.dvsClientSecret, identityData.curve);
        token = this.crypto.extractPin(identityData.mpinId, keypair.publicKey, userPin, csHex, identityData.curve);
    } catch (err) {
        return callback(err, null);
    }

    const userData = {
        mpinId: identityData.mpinId,
        token: token,
        curve: identityData.curve,
        dtas: identityData.dtas,
        publicKey: keypair.publicKey,
        pinLength: identityData.pinLength,
        projectId: identityData.projectId,
        verificationType: identityData.verificationType,
        state: this.users.states.register,
        nowTime: identityData.nowTime,
        updated: Math.floor(Date.now() / 1000)
    };
    this.users.write(userId, userData);

    callback(null, userData);
};

/**
 * Authenticate the user with the specified User ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticate = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["jwt"], callback);
};

/**
 * Authenticate the user for the session specified by the qrCode parameter
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} qrCode - The QR code URL that initiated the authentication
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithQRCode = function (userId, qrCode, userPin, callback) {
    this.setAccessId(qrCode.split("#").pop());
    this._authentication(userId, userPin, ["oidc"], callback);
};

/**
 * Authenticate the user for the session specified by the appLink parameter
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} appLink - The app link that initiated the authentication
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithAppLink = function (userId, appLink, userPin, callback) {
    this.setAccessId(appLink.split("#").pop());
    this._authentication(userId, userPin, ["oidc"], callback);
};

/**
 * Authenticate the session specified by the push notification payload
 *
 * @param {[key: string]: string} payload - The push notification payload
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticateWithNotificationPayload = function (payload, userPin, callback) {
    if (!payload || !payload["userID"] || !payload["qrURL"]) {
        return callback(new Error("Invalid push notification payload"), null);
    }

    this.setAccessId(payload["qrURL"].split("#").pop());
    this._authentication(payload["userID"], userPin, ["oidc"], callback);
};

/**
 * Fetch a registration (bootstrap) code for the specified User ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateQuickCode = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["reg-code"], (err, result) => {
        if (err) {
            return callback(err, null);
        }

        this.http.request({
            url: this.options.projectUrl + "/verification/quickcode",
            type: "POST",
            data: {
                projectId: this.options.projectId,
                jwt: result.jwt,
                deviceName: this._getDeviceName()
            }
        }, (err, result) => {
            if (err) {
                return callback(err, null);
            }

            callback(null, {
                code: result.code,
                expireTime: result.expireTime,
                ttlSeconds: result.ttlSeconds,
                // Deprecated, kept for backward compatibility
                OTP: result.code
            });
        });
    });
};

Client.prototype._authentication = function (userId, userPin, scope, callback) {
    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!this.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    const identityData = this.users.get(userId);

    const SEC = [], X = [];

    this._getPass1(identityData, userPin, scope, X, SEC, (err, pass1Data) => {
        if (err) {
            if (pass1Data && pass1Data.error === "EXPIRED_MPINID") {
                this.users.write(userId, { state: this.users.states.revoked });
                return callback(new Error("Revoked", { cause: err }), null);
            }

            return callback(new Error("Authentication fail", { cause: err }), null);
        }

        this._getPass2(identityData, scope, pass1Data.y, X, SEC, (err, pass2Data) => {
            if (err) {
                return callback(new Error("Authentication fail", { cause: err }), null);
            }

            this._finishAuthentication(userId, userPin, scope, pass2Data.authOTT, (err, result) => {
                if (err) {
                    if (result && result.error === "UNSUCCESSFUL_AUTHENTICATION") {
                        return callback(new Error("Unsuccessful authentication", { cause: err }), null);
                    }

                    if (result && result.error === "REVOKED_MPINID") {
                        this.users.write(userId, { state: this.users.states.revoked });
                        return callback(new Error("Revoked", { cause: err }), null);
                    }

                    return callback(new Error("Authentication fail", { cause: err }), null);
                }

                callback(null, result);
            });
        });
    });
};

/**
 * Make a request for pass one of the M-PIN protocol
 *
 * This function assigns a random value to the property X. It assigns the sum of the Client Secret
 * and time permit to the property SEC. It also
 * calculates the values U and UT which are required for M-Pin authentication,
 * where U = X.(map_to_curve(MPIN_ID)) and UT = X.(map_to_curve(MPIN_ID) + map_to_curve(DATE|sha256(MPIN_ID))
 * UT is called the commitment. U is required for finding the PIN error.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex,   // Hex-encoded M-PIN ID
 *    dtas: dtaList         // Identifier of the DTAs used for this identity
 *    UT: UT_hex,           // Hex-encoded UT
 *    U: U_hex,             // Hex-encoded U
 *    publicKey: publicKey, // The public key used for DVS
 *    scope: ['oidc']       // Scope of the authentication
 * }
 * @private
 */
Client.prototype._getPass1 = function (identityData, userPin, scope, X, SEC, callback) {
    let res;

    try {
        res = this.crypto.calculatePass1(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, X, SEC);
    } catch (err) {
        return callback(err, null);
    }

    const requestData = {
        scope: scope,
        mpin_id: identityData.mpinId, // eslint-disable-line camelcase
        dtas: identityData.dtas, // eslint-disable-line camelcase
        publicKey: identityData.publicKey,
        UT: res.UT,
        U: res.U
    };

    this.http.request({ url: this.options.projectUrl + "/rps/v2/pass1", type: "POST", data: requestData }, callback);
};

/**
 * Make a request for pass two of the M-Pin protocol
 *
 * This function uses the random value y from the server, property X
 * and the combined Client Secret and time permit to calculate
 * the value V which is sent to the M-PIN server.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex, // Hex-encoded M-PIN ID
 *    V: V_hex,           // Value required by the server to authenticate user
 *    WID: accessNumber   // Number required for mobile authentication
 * }
 * @private
 */
Client.prototype._getPass2 = function (identityData, scope, yHex, X, SEC, callback) {
    let vHex;

    try {
        vHex = this.crypto.calculatePass2(identityData.curve, X, yHex, SEC);
    } catch (err) {
        return callback(err, null);
    }

    const requestData = {
        mpin_id: identityData.mpinId, // eslint-disable-line camelcase
        WID: this.session.accessId,
        V: vHex
    };

    this.http.request({ url: this.options.projectUrl + "/rps/v2/pass2", type: "POST", data: requestData}, callback);
};

Client.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
    const requestData = {
        "authOTT": authOTT,
        "wam": "dvs"
    };

    this.http.request({ url: this.options.projectUrl + "/rps/v2/authenticate", type: "POST", data: requestData }, (err, result) => {
        if (err) {
            return callback(err, result);
        }

        if (result.dvsRegister) {
            this._renewSecret(userId, userPin, result.dvsRegister, (err) => {
                if (err) {
                    return callback(err, null);
                }

                this._authentication(userId, userPin, scope, callback);
            });
        } else {
            this.users.updateLastUsed(userId);
            callback(null, result);
        }
    });
};

Client.prototype._renewSecret = function (userId, userPin, activationData, callback) {
    const keypair = this.crypto.generateKeypair(activationData.curve);

    this._createMPinID(userId, activationData.token, keypair, (err, identityData) => {
        if (err) {
            return callback(err, null);
        }

        this._getSecret(identityData.secretUrls[0], (err, sec1Data) => {
            if (err) {
                return callback(err, null);
            }

            this._getSecret(identityData.secretUrls[1], (err, sec2Data) => {
                if (err) {
                    return callback(err, null);
                }

                this._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
            });
        });
    });
};

/**
 * Create a cryptographic signature of a given message
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {string} message - The message that will be signed
 * @param {number} timestamp - The creation timestamp of the message
 * @param {function(Error, Object)} callback
 */
Client.prototype.sign = function (userId, userPin, message, timestamp, callback) {
    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!this.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    if (!message) {
        return callback(new Error("Empty message"), null);
    }

    const identityData = this.users.get(userId);

    if (!identityData.publicKey) {
        return callback(new Error("Empty public key"), null);
    }

    this._authentication(userId, userPin, ["dvs-auth"], (err) => {
        if (err) {
            switch (err.message) {
                case "Unsuccessful authentication":
                case "Revoked":
                    return callback(err, null);

                default:
                    return callback(new Error("Signing fail", { cause: err.cause }), null);
            }
        }

        let res;

        try {
            res = this.crypto.sign(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, message, timestamp);
        } catch (err) {
            return callback(new Error("Signing fail", { cause: err }), null);
        }

        const signatureData = {
            hash: message,
            u: res.U,
            v: res.V,
            mpinId: identityData.mpinId,
            publicKey: identityData.publicKey,
            dtas: identityData.dtas
        };

        callback(null, signatureData);
    });
};

Client.prototype._urlEncode = function (obj) {
    const str = [];

    for (const p in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, p)) {
            str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
        }
    }

    return str.join("&");
};

Client.prototype._parseUriParams = function (uri) {
    const query = uri.split("?").pop();
    const queryArr = query.split("&");

    const params = {};

    if (!query.length || !queryArr.length) {
        return params;
    }

    for (let i = 0; i < queryArr.length; i++) {
        const pairArr = queryArr[i].split("=");
        params[pairArr[0]] = decodeURIComponent(pairArr[1].replace(/\+/g, " "));
    }

    return params;
};
