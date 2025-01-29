import Crypto from "./crypto.js";
import Users from "./users.js";
import HTTP from "./http.js";

/**
 * @class
 * @param {Object} options
 * @param {string} options.server - Server address, defaults to https://api.mpin.io
 * @param {string} options.projectId - MIRACL Trust Project ID
 * @param {string} options.seed - Hex encoded random number generator seed
 * @param {string} options.deviceName - Name of the current device
 * @param {Object} options.userStorage - Storage for saving user data
 * @param {Object} options.oidc - Parameters for initializing an OIDC auth session
 * @param {string} options.oidc.client_id - OIDC client ID
 * @param {string} options.oidc.redirect_uri - OIDC redirect URI
 * @param {string} options.oidc.response_type - OIDC response type. Only 'code' is supported
 * @param {string} options.oidc.scope - OIDC scope. Must include 'openid'
 * @param {string} options.oidc.state - OIDC state
 * @param {bool}   options.cors - Enable CORS requests if set to 'true'
 * @param {number} options.requestTimeout - Time before a HTTP request times out in miliseconds
 * @param {string} options.applicationInfo - Sets additional information that will be sent via X-MIRACL-CLIENT HTTP header
 */
export default function Client(options) {
    var self = this;

    if (!options) {
        throw new Error("Invalid configuration");
    }

    if (!options.projectId) {
        throw new Error("Empty project ID");
    }

    if (!options.userStorage) {
        throw new Error("Invalid user storage");
    }

    if (!options.server) {
        options.server = "https://api.mpin.io";
    } else {
        // remove trailing slash from url, if there is one
        options.server = options.server.replace(/\/$/, "");
    }

    // Ensure that default PIN lenght is between 4 and 6
    if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
        options.defaultPinLength = 4;
    }

    if (!options.requestTimeout || isNaN(options.requestTimeout)) {
        options.requestTimeout = 4000;
    }

    // Set the client name using the current lib version and provided application info
    options.clientName = "MIRACL Client.js/8.4.0" + (options.applicationInfo ? " " + options.applicationInfo : "");

    self.options = options;

    self.http = new HTTP(options.requestTimeout, options.clientName, options.projectId, options.cors);

    self.crypto = new Crypto(options.seed);

    self.users = new Users(options.userStorage, options.projectId, "mfa");
}

Client.prototype.options = {};

Client.prototype.session = {};

/**
 * Set the access(session) ID
 *
 * @param {string} accessId
 */
Client.prototype.setAccessId = function (accessId) {
    this.session.accessId = accessId;
};

/**
 * Make a request to start a new session and fetch the access(session) ID
 *
 * @param {string} userId - The unique identifier of the user that will be authenticating (not required)
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchAccessId = function (userId, callback) {
    var self = this,
        reqData;

    reqData = {
        url: self.options.server + "/rps/v2/session",
        type: "POST",
        data: {
            projectId: self.options.projectId,
            userId: userId
        }
    };

    self.http.request(reqData, function (error, res) {
        if (error) {
            return callback(error, null);
        }

        self.session = res;

        callback(null, res);
    });
};

/**
 * Request for changes in status
 *
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchStatus = function (callback) {
    var self = this,
        reqData;

    reqData = {
        url: self.options.server + "/rps/v2/access",
        type: "POST",
        data: {
            webOTT: self.session.webOTT
        }
    };

    self.http.request(reqData, function (error, data) {
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
    var self = this,
        reqData;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    reqData = {
        url: self.options.server + "/pushauth?" + self._urlEncode(self.options.oidc),
        type: "POST",
        data: {
            prerollId: userId
        }
    };

    self.http.request(reqData, function (err, result) {
        if (err) {
            if (result && result.error === "NO_PUSH_TOKEN") {
                return callback(new Error("No push token", { cause: err }));
            }

            return callback(err, null);
        }

        self.session.webOTT = result.webOTT;

        callback(null, result);
    });
};

/**
 * Start the verification process for a specified user ID (must be email)
 *
 * @param {string} userId - The email to start verification for
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendVerificationEmail = function (userId, callback) {
    var self = this,
        reqData = {};

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    reqData.url = self.options.server + "/verification/email";
    reqData.type = "POST";
    reqData.data = {
        userId: userId,
        mpinId: self.users.get(userId, "mpinId"),
        projectId: self.options.projectId,
        accessId: self.session.accessId,
        deviceName: self._getDeviceName(),
        clientId: self.options.oidc["client_id"],
        redirectURI: self.options.oidc["redirect_uri"],
        scope: self.options.oidc["scope"] ? self.options.oidc["scope"].split(" ") : [],
        state: self.options.oidc["state"],
        nonce: self.options.oidc["nonce"]
    };

    self.http.request(reqData, function (err, result) {
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
    var self = this,
        reqData = {},
        params;

    params = self._parseUriParams(verificationURI);

    if (!params["user_id"]) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!params["code"]) {
        return callback(new Error("Empty verification code"), null);
    }

    reqData.url = self.options.server + "/verification/confirmation";
    reqData.type = "POST";
    reqData.data = {
        userId: params["user_id"],
        code: params["code"]
    };

    self.http.request(reqData, function (err, result) {
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
 * Create an identity for the specified user ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} activationToken - The code received from the verification process
 * @param {function} pinCallback - Called when the PIN code needs to be entered
 * @param {function(Error, Object)} callback
 */
Client.prototype.register = function (userId, activationToken, pinCallback, callback) {
    var self = this,
        keypair;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!activationToken) {
        return callback(new Error("Empty activation token"), null);
    }

    keypair = self.crypto.generateKeypair("BN254CX");

    self._createMPinID(userId, activationToken, function (err, identityData) {
        if (err) {
            if (identityData && identityData.error === "INVALID_ACTIVATION_TOKEN") {
                return callback(new Error("Invalid activation token", { cause: err }), null);
            }

            return callback(new Error("Registration fail", { cause: err }), null);
        }

        if (identityData.projectId !== self.options.projectId) {
            return callback(new Error("Project mismatch"), null);
        }

        self._getSecret1(identityData, keypair, function (err, sec1Data) {
            if (err) {
                return callback(new Error("Registration fail", { cause: err }), null);
            }

            self._getSecret2(sec1Data, function (err, sec2Data) {
                if (err) {
                    return callback(new Error("Registration fail", { cause: err }), null);
                }

                var pinLength,
                    passPin;

                pinLength = identityData.pinLength;
                if (!pinLength) {
                    pinLength = self.options.defaultPinLength;
                }

                // should be called to continue the flow
                // after a PIN was provided
                passPin = function (userPin) {
                    self._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
                };

                pinCallback(passPin, pinLength);
            });
        });
    });
};

Client.prototype._createMPinID = function (userId, activationToken, callback) {
    var self = this,
        regData = {};

    regData.url = self.options.server + "/rps/v2/user";
    regData.type = "PUT";
    regData.data = {
        userId: userId,
        mobile: 0,
        deviceName: self._getDeviceName(),
        activateCode: activationToken
    };

    self.http.request(regData, function (err, result) {
        if (err) {
            return callback(err, result);
        }

        self.users.write(userId, { state: self.users.states.start });

        callback(null, result);
    });
};

Client.prototype._getDeviceName = function () {
    var self = this;

    if (self.options.deviceName) {
        return self.options.deviceName;
    }

    return "Browser";
};

Client.prototype._getSecret1 = function (identityData, keypair, callback) {
    var self = this,
        cs1Url;

    cs1Url = self.options.server + "/rps/v2/signature/";
    cs1Url += identityData.mpinId;
    cs1Url += "?regOTT=" + identityData.regOTT;
    cs1Url += "&publicKey=" + keypair.publicKey;

    self.http.request({ url: cs1Url }, function (err, sec1Data) {
        if (err) {
            return callback(err, null);
        }

        callback(null, sec1Data);
    });
};

Client.prototype._getSecret2 = function (sec1Data, callback) {
    var self = this;

    self.http.request({ url: sec1Data.cs2url }, callback);
};

Client.prototype._createIdentity = function (userId, userPin, identityData, sec1Data, sec2Data, keypair, callback) {
    var self = this,
        userData,
        csHex,
        token;

    try {
        csHex = self.crypto.addShares(keypair.privateKey, sec1Data.dvsClientSecretShare, sec2Data.dvsClientSecret, sec1Data.curve);
        token = self.crypto.extractPin(identityData.mpinId, keypair.publicKey, userPin, csHex, sec1Data.curve);
    } catch (err) {
        return callback(err, null);
    }

    userData = {
        mpinId: identityData.mpinId,
        token: token,
        curve: sec1Data.curve,
        dtas: sec1Data.dtas,
        publicKey: keypair.publicKey,
        pinLength: identityData.pinLength,
        projectId: identityData.projectId,
        verificationType: identityData.verificationType,
        state: self.users.states.register,
        nowTime: identityData.nowTime,
        updated: Math.floor(Date.now() / 1000)
    };
    self.users.write(userId, userData);

    callback(null, userData);
};

/**
 * Authenticate the user with the specified user ID
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
 * Fetch a registration (bootstrap) code for the specified user ID
 *
 * @param {string} userId - The unique identifier of the user
 * @param {string} userPin - The PIN associated with the userId
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateQuickCode = function (userId, userPin, callback) {
    var self = this;

    self._authentication(userId, userPin, ["reg-code"], function (err, result) {
        if (err) {
            return callback(err, null);
        }

        self.http.request({
            url: self.options.server + "/verification/quickcode",
            type: "POST",
            data: {
                projectId: self.options.projectId,
                jwt: result.jwt,
                deviceName: self._getDeviceName()
            }
        }, function (err, result) {
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
    var self = this,
        identityData,
        SEC = [],
        X = [];

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!self.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    identityData = self.users.get(userId);

    self._getPass1(identityData, userPin, scope, X, SEC, function (err, pass1Data) {
        if (err) {
            if (pass1Data && pass1Data.error === "EXPIRED_MPINID") {
                self.users.write(userId, { state: self.users.states.revoked });
                return callback(new Error("Revoked", { cause: err }), null);
            }

            return callback(new Error("Authentication fail", { cause: err }), null);
        }

        self._getPass2(identityData, scope, pass1Data.y, X, SEC, function (err, pass2Data) {
            if (err) {
                return callback(new Error("Authentication fail", { cause: err }), null);
            }

            self._finishAuthentication(userId, userPin, scope, pass2Data.authOTT, function (err, result) {
                if (err) {
                    if (result && result.error === "UNSUCCESSFUL_AUTHENTICATION") {
                        return callback(new Error("Unsuccessful authentication", { cause: err }), null);
                    }

                    if (result && result.error === "REVOKED_MPINID") {
                        self.users.write(userId, { state: self.users.states.revoked });
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
 * Make a request for pass one of the M-Pin protocol
 *
 * This function assigns to the property X a random value. It assigns to
 * the property SEC the sum of the client secret and time permit. It also
 * calculates the values U and UT which are required for M-Pin authentication,
 * where U = X.(map_to_curve(MPIN_ID)) and UT = X.(map_to_curve(MPIN_ID) + map_to_curve(DATE|sha256(MPIN_ID))
 * UT is called the commitment. U is the required for finding the PIN error.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex,   // Hex encoded M-Pin ID
 *    dtas: dtaList         // Identifier of the DTAs used for this identity
 *    UT: UT_hex,           // Hex encoded UT
 *    U: U_hex,             // Hex encoded U
 *    publicKey: publicKey, // The public key used for DVS
 *    scope: ['oidc']       // Scope of the authentication
 * }
 * @private
 */
Client.prototype._getPass1 = function (identityData, userPin, scope, X, SEC, callback) {
    var self = this,
        res,
        requestData;

    try {
        res = self.crypto.calculatePass1(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, X, SEC);
    } catch (err) {
        return callback(err, null);
    }

    requestData = {
        scope: scope,
        mpin_id: identityData.mpinId,
        dtas: identityData.dtas,
        publicKey: identityData.publicKey,
        UT: res.UT,
        U: res.U
    };

    self.http.request({ url: self.options.server + "/rps/v2/pass1", type: "POST", data: requestData }, callback);
};

/**
 * Make a request for pass two of the M-Pin protocol
 *
 * This function uses the random value y from the server, property X
 * and the combined client secret and time permit to calculate
 * the value V which is sent to the M-Pin server.
 *
 * Request data has the following structure:
 * {
 *    mpin_id: mpinIdHex, // Hex encoded M-Pin ID
 *    V: V_hex,           // Value required by the server to authenticate user
 *    WID: accessNumber   // Number required for mobile authentication
 * }
 * @private
 */
Client.prototype._getPass2 = function (identityData, scope, yHex, X, SEC, callback) {
    var self = this,
        vHex,
        requestData;

    try {
        vHex = self.crypto.calculatePass2(identityData.curve, X, yHex, SEC);
    } catch (err) {
        return callback(err, null);
    }

    requestData = {
        mpin_id: identityData.mpinId,
        WID: self.session.accessId,
        V: vHex
    };

    self.http.request({ url: self.options.server + "/rps/v2/pass2", type: "POST", data: requestData}, callback);
};

Client.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
    var self = this,
        requestData;

    requestData = {
        "authOTT": authOTT,
        "wam": "dvs"
    };

    self.http.request({ url: self.options.server + "/rps/v2/authenticate", type: "POST", data: requestData }, function (err, result) {
        if (err) {
            return callback(err, result);
        }

        if (result.dvsRegister) {
            self._renewSecret(userId, userPin, result.dvsRegister, function(err) {
                if (err) {
                    return callback(err, null);
                }

                self._authentication(userId, userPin, scope, callback);
            });
        } else {
            self.users.updateLastUsed(userId);
            callback(null, result);
        }
    });
};

Client.prototype._renewSecret = function (userId, userPin, activationData, callback) {
    var self = this,
        identityData,
        keypair;

    identityData = self.users.get(userId);
    keypair = self.crypto.generateKeypair(activationData.curve);

    self._getWaMSecret1(keypair, activationData.token, function (err, sec1Data) {
        if (err) {
            return callback(err, null);
        }

        self._getSecret2(sec1Data, function (err, sec2Data) {
            if (err) {
                return callback(err, null);
            }

            self._createIdentity(userId, userPin, identityData, sec1Data, sec2Data, keypair, callback);
        });
    });
};

Client.prototype._getWaMSecret1 = function (keypair, registerToken, callback) {
    var self = this,
        cs1Url,
        reqData;

    reqData = {
        publicKey: keypair.publicKey,
        dvsRegisterToken: registerToken
    };

    cs1Url = self.options.server + "/rps/v2/dvsregister";

    self.http.request({ url: cs1Url, type: "POST", data: reqData }, callback);
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
    var self = this,
        identityData;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!self.users.exists(userId)) {
        return callback(new Error("User not found"), null);
    }

    if (!message) {
        return callback(new Error("Empty message"), null);
    }

    identityData = self.users.get(userId);

    if (!identityData.publicKey) {
        return callback(new Error("Empty public key"), null);
    }

    this._authentication(userId, userPin, ["dvs-auth"], function (err) {
        var res,
            signatureData;

        if (err) {
            switch (err.message) {
                case "Unsuccessful authentication":
                case "Revoked":
                    return callback(err, null);

                default:
                    return callback(new Error("Signing fail", { cause: err.cause }), null);
            }
        }

        try {
            res = self.crypto.sign(identityData.curve, identityData.mpinId, identityData.publicKey, identityData.token, userPin, message, timestamp);
        } catch (err) {
            return callback(new Error("Signing fail", { cause: err }), null);
        }

        signatureData = {
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
    var str = [],
        p;

    for (p in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, p)) {
            str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
        }
    }

    return str.join("&");
};

Client.prototype._parseUriParams = function (uri) {
    var query = uri.split("?").pop(),
        queryArr = query.split("&"),
        params = {},
        pairArr,
        i;

    if (!query.length || !queryArr.length) {
        return params;
    }

    for (i = 0; i < queryArr.length; i++) {
        pairArr = queryArr[i].split("=");
        params[pairArr[0]] = decodeURIComponent(pairArr[1].replace(/\+/g, " "));
    }

    return params;
};
