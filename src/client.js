import Crypto from "./crypto.js";
import Users from "./users.js";

var RequestError = createErrorType("RequestError", ["message", "status"]),
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
 * @param {string} options.applicationInfo - Sets additional information that will be sent via X-MIRACL-CLIENT HTTP header
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

    // Set the client name using the current lib version and provided application info
    options.clientName = "MIRACL Client.js/7.4.0" + (options.applicationInfo ? " " + options.applicationInfo : "");

    self.options = options;

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
        projectId: self.options.projectId,
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
        code: params["code"]
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
    var self = this,
        keypair;

    if (!userId) {
        throw new Error("Missing user ID");
    }

    keypair = self.crypto.generateKeypair("BN254CX");

    self._createMPinID(userId, activationToken, function (err, identityData) {
        if (err) {
            return callback(err, null);
        }

        self._getSecret1(identityData, keypair, function (err, sec1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getSecret2(sec1Data, function (err, sec2Data) {
                if (err) {
                    return callback(err, null);
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

    self._request(regData, function (err, data) {
        if (err) {
            if (err.status === 403) {
                return callback(new InvalidRegCodeError("Invalid registration code"), null);
            } else {
                return callback(err, null);
            }
        }

        if (data.projectId !== self.options.projectId) {
            return callback(new InvalidRegCodeError("Registration started for different project"), null);
        }

        self.users.write(userId, { state: self.users.states.start });

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

Client.prototype._getSecret1 = function (identityData, keypair, callback) {
    var self = this,
        cs1Url;

    cs1Url = self.options.server + "/rps/v2/signature/";
    cs1Url += identityData.mpinId;
    cs1Url += "?regOTT=" + identityData.regOTT;
    cs1Url += "&publicKey=" + keypair.publicKey;

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
        identityData,
        SEC = [],
        X = [];

    if (!self.users.exists(userId)) {
        return callback(new IdentityError("Missing identity"), null);
    }

    identityData = self.users.get(userId);

    self._getPass1(identityData, userPin, scope, X, SEC, function (err, pass1Data) {
        if (err) {
            return callback(err, null);
        }

        self._getPass2(identityData, scope, pass1Data.y, X, SEC, function (err, pass2Data) {
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

    self._request({ url: self.options.server + "/rps/v2/pass2", type: "POST", data: requestData}, callback);
};

Client.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
    var self = this,
        requestData;

    requestData = {
        "authOTT": authOTT,
        "wam": "dvs"
    };

    self._request({ url: self.options.server + "/rps/v2/authenticate", type: "POST", data: requestData }, function (err, data) {
        if (err) {
            // Revoked identity
            if (err.status === 410) {
                self.users.write(userId, { state: self.users.states.revoked });
            }

            return callback(err, null);
        }

        if (data.dvsRegister) {
            self._renewSecret(userId, userPin, data.dvsRegister, function(err) {
                if (err) {
                    return callback(err, null);
                }

                self._authentication(userId, userPin, scope, callback);
            });
        } else {
            self.users.updateLastUsed(userId);
            callback(null, data);
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

    self._request({ url: cs1Url, type: "POST", data: reqData }, callback);
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
        identityData,
        res,
        signatureData;

    if (!userId) {
        return callback(new Error("Empty user ID"), null);
    }

    if (!self.users.exists(userId)) {
        return callback(new Error("User ID not found"), null);
    }

    identityData = self.users.get(userId);

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

    this._authentication(userId, userPin, ["dvs-auth"], function (err) {
        if (err) {
            // TODO: remap specific authentication errors
            return callback(new Error("Signing fail", { cause: err.cause }), null);
        }

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
                response = JSON.parse(request.responseText);

                if (typeof response.error === "object") {
                    description = response.error.info;
                } else {
                    description = response.error;
                }
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
    request.setRequestHeader("X-MIRACL-CLIENT", self.options.clientName);

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
