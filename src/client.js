import CTX from "@miracl/crypto-js";
import Users from "./users.js";

var CryptoContexts = {},
    RequestError = createErrorType("RequestError", ["message", "status"]),
    CryptoError = createErrorType("CryptoError", ["message", "code"]),
    NotVerifiedError = createErrorType("NotVerifiedError", ["message"]),
    VerificationExpiredError = createErrorType("VerificationExpiredError", ["message"]),
    IdentityError = createErrorType("IdentityError", ["message"]),
    InvalidRegCodeError = createErrorType("InvalidRegCodeError", ["message"]);

function createErrorType(name, params) {
    function CustomError() {
        for (var i = 0; i < params.length; ++i) {
            this[params[i]] = arguments[i] || "";
        }

        this.stack = (new Error()).stack;
    }

    CustomError.prototype = new Error;
    CustomError.prototype.name = name;
    CustomError.prototype.constructor = CustomError;

    return CustomError;
}

/**
 * @class
 * @param {Object} options
 * @param {string} options.server - Server address, defaults to https://api.mpin.io
 * @param {string} options.projectId - MIRACL Trust project ID
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
 */
export default function Client(options) {
    var self = this;

    if (!options) {
        throw new Error("Missing options");
    }

    if (!options.projectId) {
        throw new Error("Missing project ID");
    }

    if (!options.userStorage) {
        throw new Error("Missing user storage object");
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

    self.options = options;

    // Initialize RNG
    self.rng = new (self._crypto().RAND)();
    self.rng.clean();

    self.users = new Users(options.userStorage, options.projectId, "mfa");
    self.dvsUsers = new Users(options.userStorage, options.projectId, "dvs");
}

Client.prototype.options = {};

Client.prototype.session = {};

Client.prototype._crypto = function (curve) {
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

/**
 * Seed the Random Number Generator (RNG)
 * @private
 */
Client.prototype._seedRNG = function (seedHex) {
    var self = this,
        entropyBytes;

    seedHex = seedHex + self.options.seed;

    entropyBytes = self._hexToBytes(seedHex);
    self.rng.seed(entropyBytes.length, entropyBytes);
};

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
 * @param {string} userId - The ID of the user that will be authenticating (not required)
 * @param {function(Error, Object)} callback
 */
Client.prototype.fetchAccessId = function (userId, callback) {
    var self = this,
        reqData;

    reqData = {
        url: self.options.server + "/authorize?" + self._urlEncode(self.options.oidc),
        type: "POST",
        data: {
            prerollId: userId,
            registerOnly: self.options.registerOnly ? true : false
        }
    };

    self._request(reqData, function (error, res) {
        if (error) {
            return callback(error, null);
        }

        if (!res.webOTT || !res.accessURL || !res.qrURL || !res.accessId) {
            return callback(new Error("Missing initial request params"), null);
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

    self._request(reqData, function (error, data) {
        if (error) {
            return callback(error, null);
        }

        if (!data || !data.status) {
            return callback(new Error("Missing status data"), null);
        }

        callback(null, data);
    });
};

/**
 * Start the push authentication flow
 *
 * @param {string} userId - The ID of the user that will be authenticating
 * @param {function(Error, Object)} callback
 */
Client.prototype.sendPushNotificationForAuth = function (userId, callback) {
    var self = this,
        reqData;

    if (!userId) {
        return callback(new Error("Missing user ID"), null);
    }

    reqData = {
        url: self.options.server + "/pushauth?" + self._urlEncode(self.options.oidc),
        type: "POST",
        data: {
            prerollId: userId
        }
    };

    self._request(reqData, function (err, result) {
        if (err) {
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

    reqData.url = self.options.server + "/verification";
    reqData.type = "POST";
    reqData.data = {
        userId: userId,
        clientId: self.options.oidc.client_id,
        redirectURI: self.options.oidc.redirect_uri,
        accessId: self.session.accessId,
        deviceName: self._getDeviceName()
    };

    self._request(reqData, callback);
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

    reqData.url = self.options.server + "/verification/confirmation";
    reqData.type = "POST";
    reqData.data = {
        userId: params["user_id"],
        code: params["code"],
        clientId: params["client_id"],
        redirectUri: params["redirect_uri"],
        state: params["state"],
        stage: params["stage"],
    };

    self._request(reqData, function (err, data) {
        if (err) {
            return callback(err, data);
        }

        data.userId = params["user_id"];
        callback(null, data);
    });
};

/**
 * Create an identity for the specified user ID
 *
 * @param {string} userId - The ID of the user
 * @param {string} activationToken - The code received from the verification process
 * @param {function} pinCallback - Called when the PIN code needs to be entered
 * @param {function(Error, Object)} callback
 */
Client.prototype.register = function (userId, activationToken, pinCallback, callback) {
    var self = this;

    if (!userId) {
        throw new Error("Missing user ID");
    }

    self._registration(userId, activationToken, function (err, regData) {
        if (err) {
            return callback(err, null);
        }

        self._getSecret1(userId, regData, function (err, sec1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getSecret2(sec1Data, function (err, sec2Data) {
                if (err) {
                    return callback(err, null);
                }

                var pinLength,
                    passPin;

                pinLength = self.users.get(userId, "pinLength");
                if (!pinLength) {
                    pinLength = self.options.defaultPinLength;
                }

                // should be called to continue the flow
                // after a PIN was provided
                passPin = function (userPin) {
                    self._createIdentity(userId, userPin, sec1Data, sec2Data, callback);
                };

                pinCallback(passPin, pinLength);
            });
        });
    });
};

Client.prototype._registration = function (userId, activationToken, callback) {
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

    self._request(regData, function (err, data) {
        if (err) {
            if (activationToken && err.status === 403) {
                return callback(new InvalidRegCodeError("Invalid registration code"), null);
            } else {
                return callback(err, null);
            }
        }

        data.state = (data.active) ? self.users.states.active : self.users.states.start;
        self.users.write(userId, data);

        callback(null, data);
    });
};

Client.prototype._getDeviceName = function () {
    var self = this;

    if (self.options.deviceName) {
        return self.options.deviceName;
    }

    return "Browser";
};

Client.prototype._getSecret1 = function (userId, regData, callback) {
    var self = this,
        cs1Url;

    cs1Url = self.options.server + "/rps/v2/signature/";
    cs1Url += self.users.get(userId, "mpinId");
    cs1Url += "?regOTT=" + regData.regOTT;

    self._request({ url: cs1Url }, function (err, sec1Data) {
        if (err) {
            if (err.status === 401) {
                return callback(new NotVerifiedError("Identity not verified"), null);
            } else if (err.status === 404) {
                return callback(new VerificationExpiredError("Registration session expired"), null);
            } else {
                return callback(err, null);
            }
        }

        callback(null, sec1Data);
    });
};

Client.prototype._getSecret2 = function (sec1Data, callback) {
    var self = this;

    self._request({ url: sec1Data.cs2url }, callback);
};

Client.prototype._createIdentity = function (userId, userPin, sec1Data, sec2Data, callback) {
    var self = this,
        userData,
        mpinId,
        csHex,
        token;

    // TODO: test this
    if (sec1Data.mpin_id) {
        mpinId = sec1Data.mpin_id;
    } else {
        mpinId = self.users.get(userId, "mpinId");
    }

    try {
        csHex = self._addShares(sec1Data.clientSecretShare, sec2Data.clientSecret, sec1Data.curve);
        token = self._extractPin(mpinId, userPin, csHex, sec1Data.curve);
    } catch (err) {
        return callback(err, null);
    }

    userData = {
        curve: sec1Data.curve,
        dtas: sec1Data.dtas,
        mpinId: mpinId,
        state: self.users.states.register,
        token: token
    };
    self.users.write(userId, userData);

    callback(null, userData);
};

/**
 * Add two points on the curve that are originally in hex format
 * This function is used to add client secret shares.
 * Returns a hex encoded sum of the shares
 * @private
 */
Client.prototype._addShares = function (share1Hex, share2Hex, curve) {
    var self = this,
        share1Bytes = [],
        share2Bytes = [],
        sumBytes = [],
        errorCode;

    share1Bytes = self._hexToBytes(share1Hex);
    share2Bytes = self._hexToBytes(share2Hex);

    errorCode = self._crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, sumBytes);
    if (errorCode !== 0) {
        throw new CryptoError("Could not combine the client secret shares", errorCode);
    }

    return self._bytesToHex(sumBytes);
};

/**
 * Calculates the MPin Token
 * This function maps the M-Pin ID to a point on the curve,
 * multiplies this value by PIN and then subtractsit from
 * the client secret curve point to generate the M-Pin token.
 * Returns a hex encoded M-Pin Token
 * @private
 */
Client.prototype._extractPin = function (mpinIdHex, PIN, clientSecretHex, curve) {
    var self = this,
        clientSecretBytes = [],
        mpinIdBytes = [],
        errorCode;

    clientSecretBytes = self._hexToBytes(clientSecretHex);
    mpinIdBytes = self._hexToBytes(mpinIdHex);

    errorCode = self._crypto(curve).MPIN.EXTRACT_PIN(self._crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
    if (errorCode !== 0) {
        throw new CryptoError("Could not extract PIN from client secret", errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

/**
 * Authenticate the user with the specified user ID
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity
 * @param {function(Error, Object)} callback
 */
Client.prototype.authenticate = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["oidc"], callback);
};

/**
 * Authenticate the user and receive an authorization code as a result
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateAuthCode = function (userId, userPin, callback) {
    var self = this;

    self.fetchAccessId(userId, function (err) {
        if (err) {
            return callback(err, null);
        }

        self._authentication(userId, userPin, ["authcode"], callback);
    });
};

/**
 * Fetch an OTP for the specified user ID
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateOTP = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["otp"], callback);
};

/**
 * Fetch a registration (bootstrap) code for the specified user ID
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity
 * @param {function(Error, Object)} callback
 */
Client.prototype.generateQuickCode = function (userId, userPin, callback) {
    this._authentication(userId, userPin, ["reg-code"], callback);
};

Client.prototype._authentication = function (userId, userPin, scope, callback) {
    var self = this,
        userStorage,
        SEC = [],
        X = [];

    userStorage = scope.indexOf("dvs-auth") !== -1 ? self.dvsUsers : self.users;

    if (!userStorage.exists(userId)) {
        return callback(new IdentityError("Missing identity"), null);
    }

    self._getPass1(userId, userPin, scope, X, SEC, function (err, pass1Data) {
        if (err) {
            return callback(err, null);
        }

        self._getPass2(userId, scope, pass1Data.y, X, SEC, function (err, pass2Data) {
            if (err) {
                return callback(err, null);
            }

            self._finishAuthentication(userId, userPin, scope, pass2Data.authOTT, callback);
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
Client.prototype._getPass1 = function (userId, userPin, scope, X, SEC, callback) {
    var self = this,
        U = [],
        UT = [],
        userStorage,
        mpinIdHex,
        tokenHex,
        curve,
        errorCode,
        requestData;

    // Choose user storage depending on scope
    userStorage = scope.indexOf("dvs-auth") !== -1 ? self.dvsUsers : self.users;

    tokenHex = userStorage.get(userId, "token");
    curve = userStorage.get(userId, "curve");

    if (userStorage === self.users) {
        mpinIdHex = userStorage.get(userId, "mpinId");
    } else {
        mpinIdHex = self._getSignMpinId(userStorage.get(userId, "mpinId"), userStorage.get(userId, "publicKey"));
    }

    errorCode = self._crypto(curve).MPIN.CLIENT_1(self._crypto(curve).MPIN.SHA256, 0, self._hexToBytes(mpinIdHex), self.rng, X, userPin, self._hexToBytes(tokenHex), SEC, U, UT, self._hexToBytes(0));
    if (errorCode !== 0) {
        return callback(new CryptoError("Could not calculate pass 1 request data", errorCode), null);
    }

    requestData = {
        scope: scope,
        mpin_id: userStorage.get(userId, "mpinId"),
        dtas: userStorage.get(userId, "dtas"),
        publicKey: userStorage.get(userId, "publicKey"),
        UT: self._bytesToHex(UT),
        U: self._bytesToHex(U)
    };

    self._request({ url: self.options.server + "/rps/v2/pass1", type: "POST", data: requestData }, callback);
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
Client.prototype._getPass2 = function (userId, scope, yHex, X, SEC, callback) {
    var self = this,
        userStorage,
        curve,
        requestData,
        yBytes,
        errorCode;

    userStorage = scope.indexOf("dvs-auth") !== -1 ? self.dvsUsers : self.users;

    curve = userStorage.get(userId, "curve");

    yBytes = self._hexToBytes(yHex);

    // Compute V
    errorCode = self._crypto(curve).MPIN.CLIENT_2(X, yBytes, SEC);
    if (errorCode !== 0) {
        return callback(new CryptoError("Could not calculate pass 2 request data", errorCode), null);
    }

    requestData = {
        mpin_id: userStorage.get(userId, "mpinId"),
        WID: self.session.accessId,
        V: self._bytesToHex(SEC)
    };

    self._request({ url: self.options.server + "/rps/v2/pass2", type: "POST", data: requestData}, callback);
};

Client.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
    var self = this,
        requestData,
        userStorage,
        isDvsAuth;

    requestData = {
        "authOTT": authOTT
    };

    isDvsAuth = scope.indexOf("dvs-auth") !== -1;
    userStorage = isDvsAuth ? self.dvsUsers : self.users;

    self._request({ url: self.options.server + "/rps/v2/authenticate", type: "POST", data: requestData }, function (err, data) {
        if (err) {
            // Revoked identity
            if (err.status === 410) {
                userStorage.write(userId, { state: userStorage.states.revoked });
            }

            return callback(err, null);
        }

        if (data.renewSecret) {
            self._renewSecret(userId, userPin, data.renewSecret, callback);
        } else if (data.dvsRegister && isDvsAuth) {
            // Renew automatically only if signing
            self._renewDvsSecret(userId, userPin, data.dvsRegister, callback);
        } else {
            self.users.updateLastUsed(userId);
            callback(null, data);
        }
    });
};

Client.prototype._renewSecret = function (userId, userPin, sec1Data, callback) {
    var self = this;

    self._getSecret2(sec1Data, function (err, sec2Data) {
        if (err) {
            return callback(err, null);
        }

        self._createIdentity(userId, userPin, sec1Data, sec2Data, function (err) {
            if (err) {
                return callback(err, null);
            }

            self.authenticate(userId, userPin, callback);
        });
    });
};

/**
 * Register an identity capable of signing
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity used for authentication
 * @param {string} dvsPin - The PIN that will be used for the new identity
 * @param {function(Error, Object)} callback
 */
Client.prototype.signingRegister = function (userId, userPin, dvsPin, callback) {
    var self = this;

    self._authentication(userId, userPin, ["dvs-reg"], function (err, data) {
        if (err) {
            return callback(err, null);
        }

        self._renewDvsSecret(userId, dvsPin, data.dvsRegister, callback);
    });
};

Client.prototype._renewDvsSecret = function (userId, userPin, dvsRegister, callback) {
    var self = this,
        keypair;

    keypair = self._generateSignKeypair(dvsRegister.curve);

    self._getDvsSecret1(keypair, dvsRegister.token, function (err, sec1Data) {
        if (err) {
            return callback(err, null);
        }

        self._getSecret2(sec1Data, function (err, sec2Data) {
            if (err) {
                return callback(err, null);
            }

            self._createSigningIdentity(userId, userPin, sec1Data, sec2Data, keypair, callback);
        });
    });
};

Client.prototype._getDvsSecret1 = function (keypair, dvsRegisterToken, callback) {
    var self = this,
        cs1Url,
        reqData;

    reqData = {
        publicKey: keypair.publicKey,
        deviceName: self._getDeviceName(),
        dvsRegisterToken: dvsRegisterToken
    };

    cs1Url = self.options.server + "/rps/v2/dvsregister";

    self._request({ url: cs1Url, type: "POST", data: reqData }, callback);
};

Client.prototype._generateSignKeypair = function (curve) {
    var self = this,
        privateKeyBytes = [],
        publicKeyBytes = [],
        errorCode;

    errorCode = self._crypto(curve).MPIN.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
    if (errorCode != 0) {
        throw new CryptoError("Could not generate key pair", errorCode);
    }

    return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
};

Client.prototype._createSigningIdentity = function (userId, userPin, sec1Data, sec2Data, keypair, callback) {
    var self = this,
        csHex,
        token,
        signMpinId,
        userData;

    try {
        csHex = self._addShares(sec1Data.dvsClientSecretShare, sec2Data.dvsClientSecret, sec1Data.curve);
        csHex = self._generateSignClientSecret(keypair.privateKey, csHex, sec1Data.curve);
        signMpinId = self._getSignMpinId(sec1Data.mpinId, keypair.publicKey);
        token = self._extractPin(signMpinId, userPin, csHex, sec1Data.curve);
    } catch (err) {
        return callback(err, null);
    }

    userData = {
        mpinId: sec1Data.mpinId,
        dtas: sec1Data.dtas,
        curve: sec1Data.curve,
        publicKey: keypair.publicKey,
        token: token,
        state: self.dvsUsers.states.register
    };
    self.dvsUsers.write(userId, userData);

    callback(null, userData);
};

/**
 * Compute client secret for key escrow less scheme
 * @private
 */
Client.prototype._generateSignClientSecret = function (privateKeyHex, clientSecretHex, curve) {
    var self = this,
        privateKeyBytes = self._hexToBytes(privateKeyHex),
        clientSecretBytes = self._hexToBytes(clientSecretHex),
        errorCode;

    errorCode = self._crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
    if (errorCode != 0) {
        throw new CryptoError("Could not combine private key with client secret", errorCode);
    }

    return self._bytesToHex(clientSecretBytes);
};

Client.prototype._getSignMpinId = function (mpinId, publicKey) {
    var self = this,
        mpinIdBytes = self._hexToBytes(mpinId),
        publicKeyBytes = self._hexToBytes(publicKey),
        i;

    if (!mpinIdBytes || !publicKeyBytes) {
        return;
    }

    for (i = 0; i < publicKeyBytes.length; i++) {
        mpinIdBytes.push(publicKeyBytes[i]);
    }

    return self._bytesToHex(mpinIdBytes);
};

/**
 * Create a cryptographic signature of a given message
 *
 * @param {string} userId - The ID of the user
 * @param {string} userPin - The PIN of the identity used for authentication
 * @param {string} message - The message that will be signed
 * @param {number} timestamp - The creation timestamp of the message
 * @param {function(Error, Object)} callback
 */
Client.prototype.sign = function (userId, userPin, message, timestamp, callback) {
    var self = this,
        messageBytes = self._hexToBytes(message),
        mpinIdHex = self._getSignMpinId(self.dvsUsers.get(userId, "mpinId"), self.dvsUsers.get(userId, "publicKey")),
        mpinIdBytes = self._hexToBytes(mpinIdHex),
        tokenHex = self.dvsUsers.get(userId, "token"),
        tokenBytes = self._hexToBytes(tokenHex),
        curve = self.dvsUsers.get(userId, "curve"),
        SEC = [],
        X = [],
        Y1 = [],
        U = [],
        errorCode,
        signatureData;

    errorCode = self._crypto(curve).MPIN.CLIENT(self._crypto(curve).MPIN.SHA256, 0, mpinIdBytes, self.rng, X, userPin, tokenBytes, SEC, U, null, null, timestamp, Y1, messageBytes);
    if (errorCode != 0) {
        callback(new CryptoError("Could not sign message", errorCode), null);
    }

    signatureData = {
        hash: message,
        u: self._bytesToHex(U),
        v: self._bytesToHex(SEC),
        mpinId: self.dvsUsers.get(userId, "mpinId"),
        publicKey: self.dvsUsers.get(userId, "publicKey"),
        dtas: self.dvsUsers.get(userId, "dtas")
    };

    this._authentication(userId, userPin, ["dvs-auth"], function (err) {
        if (err) {
            return callback(err, null);
        }

        callback(null, signatureData);
    });
};

/**
 * Convert a hex representation of a Point to a bytes array
 * @private
 */
Client.prototype._hexToBytes = function (hexValue) {
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

Client.prototype._bytesToHex = function (b) {
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

/**
 * Make an HTTP request
 * @private
 */
Client.prototype._request = function (options, callback) {
    var self = this, url, type, request;

    if (typeof callback !== "function") {
        throw new Error("Bad or missing callback");
    }

    if (!options.url) {
        throw new Error("Missing URL for request");
    }

    request = new XMLHttpRequest();

    url = options.url;
    type = options.type || "GET";

    request.onreadystatechange = function () {
        var response,
            description;

        if (request.readyState === 4 && request.status === 200) {
            try {
                response = JSON.parse(request.responseText);
            } catch (e) {
                response = request.responseText;
            }
            callback(null, response);
        } else if (request.readyState === 4) {
            try {
                description = JSON.parse(request.responseText).error;
            } catch (e) {
                description = request.statusText;
            }

            if (request.status !== 0) {
                callback(new RequestError(description, request.status), null);
            } else {
                callback(new RequestError("The request was aborted", 0), null);
            }
        }
    };


    if (self.options.cors) {
        url += (url.indexOf("?") !== -1 ? "&" : "?") + "project_id=" + self.options.projectId;
    }

    request.open(type, url, true);

    request.timeout = self.options.requestTimeout;

    request.setRequestHeader("X-MIRACL-CID", self.options.projectId);

    // Set authorization header if provided
    if (options.authorization) {
        request.setRequestHeader("Authorization", options.authorization);
    }

    if (options.data) {
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(options.data));
    } else {
        request.send();
    }

    return request;
};
