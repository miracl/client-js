var Mfa = Mfa || {};

(function() {
    "use strict";

    var CryptoContexts = {},
        RequestError = createErrorType("RequestError", ["message", "status"]),
        CryptoError = createErrorType("CryptoError", ["message", "code"]),
        NotVerifiedError = createErrorType("NotVerifiedError", ["message"]),
        VerificationExpiredError = createErrorType("VerificationExpiredError", ["message"]),
        IdentityError = createErrorType("IdentityError", ["message"]),
        InvalidRegCodeError = createErrorType("InvalidRegCodeError", ["message"]),
        Users;

    function createErrorType(name, params) {
        function CustomError() {
            for (var i = 0; i < params.length; ++i)  {
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
     * @param {string} options.server - Server address https://api.mpin.io
     * @param {string} options.customerId - Customer ID
     * @param {string} options.seed - Hex encoded random number generator seed
     * @param {Object} options.userStorage - Storage for saving user data
     * @param {string} options.deviceName - Name of Device
     */
    Mfa = function (options) {
        var self = this;

        if (!options) {
            throw new Error("Missing options");
        }

        if (!options.server) {
            throw new Error("Missing server address");
        }

        if (!options.customerId) {
            throw new Error("Missing customer ID");
        }

        if (!options.userStorage) {
            throw new Error("Missing user storage object");
        }

        // Ensure that default PIN lenght is between 4 and 6
        if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
            options.defaultPinLength = 4;
        }

        // Initialize RNG
        self.rng = new (self.crypto().RAND)();
        self.rng.clean();

        self.users = new Users(options.userStorage, options.customerId, "mfa");
        self.dvsUsers = new Users(options.userStorage, options.customerId, "dvs");

        self.options = {};
        self.options.client = options;
    };

    Mfa.prototype.options = {};

    Mfa.prototype.crypto = function (curve) {
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
    Mfa.prototype._seedRNG = function (seedHex) {
        var self = this,
            entropyBytes;

        seedHex = seedHex + self.options.client.seed;

        entropyBytes = self._hexToBytes(seedHex);
        self.rng.seed(entropyBytes.length, entropyBytes);
    };

    Mfa.prototype._init = function (callback) {
        var self = this, settingsUrl;

        settingsUrl = self.options.client.server.replace(/\/?$/, "/");
        settingsUrl += "rps/v2/clientSettings";

        if (self.options.client.clientId) {
            settingsUrl += "?cid=" + self.options.client.clientId;
        }

        self.request({ url: settingsUrl }, function (err, settingsData) {
            if (err) {
                return callback(err, null);
            }

            self.options.settings = settingsData;
            self._seedRNG(settingsData.seedValue);

            callback(null, true);
        });
    };

    /**
     * Set the access(session) ID
     *
     * @param {string} accessId
     */
    Mfa.prototype.setAccessId = function (accessId) {
        this.accessId = accessId;
    };

    /**
     * Start the verification process for a specified user ID (must be email)
     *
     * @param {string} userId - The email to start verification for
     * @param {string} clientId - The OIDC client ID for the application
     * @param {function(Error, Object)} callback
     */
    Mfa.prototype.verify = function (userId, clientId, callback) {
        var self = this,
            reqData = {};

        reqData.url = self.options.client.server + "/verification";
        reqData.type = "POST";
        reqData.data = {
            userId: userId,
            clientId: clientId,
            accessId: self.accessId,
            deviceName: self._getDeviceName()
        };

        self.request(reqData, callback);
    };

    /**
     * Create an identity for the specified user ID
     *
     * @param {string} userId - The ID of the user
     * @param {string} registrationCode - The code received from the verification process
     * @param {function} pinCallback - Called when the PIN code needs to be entered
     * @param {function(Error, Object)} callback
     */
    Mfa.prototype.register = function (userId, registrationCode, pinCallback, callback) {
        var self = this;

        if (!userId) {
            throw new Error("Missing user ID");
        }

        self._init(function (err) {
            if (err) {
                callback(err, null);
            }

            self._registration(userId, registrationCode, function (err, regData) {
                if (err) {
                    callback(err, null);
                }

                self._getSecret1(userId, regData, function (err, sec1Data) {
                    if (err) {
                        callback(err, null);
                    }

                    self._getSecret2(sec1Data, function (err, sec2Data) {
                        if (err) {
                            callback(err, null);
                        }

                        var pinLength,
                            passPin;

                        pinLength = self.users.get(userId, "pinLength");
                        if (!pinLength) {
                            pinLength = self.options.client.defaultPinLength;
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
        });
    };

    Mfa.prototype._registration = function (userId, registrationCode, callback) {
        var self = this,
            regData = {};

        regData.url = self.options.settings.registerURL;
        regData.type = "PUT";
        regData.data = {
            userId: userId,
            wid: self.accessId,
            mobile: 0,
            deviceName: self._getDeviceName(),
            activateCode: registrationCode
        };

        self.request(regData, function (err, data) {
            if (err) {
                if (registrationCode && err.status === 403) {
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

    Mfa.prototype._getDeviceName = function () {
        var self = this;

        if (self.options.client.deviceName) {
            return self.options.client.deviceName;
        }

        return "Browser";
    };

    Mfa.prototype._getSecret1 = function (userId, regData, callback) {
        var self = this,
            cs1Url;

        cs1Url = self.options.settings.signatureURL + "/";
        cs1Url += self.users.get(userId, "mpinId");
        cs1Url += "?regOTT=" + regData.regOTT;

        self.request({ url: cs1Url }, function (err, sec1Data) {
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

    Mfa.prototype._getSecret2 = function (sec1Data, callback) {
        var self = this;

        self.request({ url: sec1Data.cs2url }, callback);
    };

    Mfa.prototype._createIdentity = function (userId, userPin, sec1Data, sec2Data, callback) {
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
    Mfa.prototype._addShares = function (share1Hex, share2Hex, curve) {
        var self = this,
            share1Bytes = [],
            share2Bytes = [],
            sumBytes = [],
            errorCode;

        share1Bytes = self._hexToBytes(share1Hex);
        share2Bytes = self._hexToBytes(share2Hex);

        errorCode = self.crypto(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, sumBytes);
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
    Mfa.prototype._extractPin = function (mpinIdHex, PIN, clientSecretHex, curve) {
        var self = this,
            clientSecretBytes = [],
            mpinIdBytes = [],
            errorCode;

        clientSecretBytes = self._hexToBytes(clientSecretHex);
        mpinIdBytes = self._hexToBytes(mpinIdHex);

        errorCode = self.crypto(curve).MPIN.EXTRACT_PIN(self.crypto(curve).MPIN.SHA256, mpinIdBytes, PIN, clientSecretBytes);
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
    Mfa.prototype.authenticate = function (userId, userPin, callback) {
        this._authentication(userId, userPin, ["oidc"], callback);
    };

    /**
     * Fetch an OTP for the specified user ID
     *
     * @param {string} userId - The ID of the user
     * @param {string} userPin - The PIN of the identity
     * @param {function(Error, Object)} callback
     */
    Mfa.prototype.fetchOTP = function (userId, userPin, callback) {
        this._authentication(userId, userPin, ["otp"], callback);
    };

    /**
     * Fetch a registration (bootstrap) code for the specified user ID
     *
     * @param {string} userId - The ID of the user
     * @param {string} userPin - The PIN of the identity
     * @param {function(Error, Object)} callback
     */
    Mfa.prototype.fetchRegistrationCode = function (userId, userPin, callback) {
        this._authentication(userId, userPin, ["reg-code"], callback);
    };

    Mfa.prototype._authentication = function (userId, userPin, scope, callback) {
        var self = this,
            userStorage,
            SEC = [],
            X = [];

        userStorage = scope.indexOf("dvs-auth") !== -1 ? self.dvsUsers : self.users;

        if (!userStorage.exists(userId)) {
            return callback(new IdentityError("Missing identity"), null);
        }

        self._init(function () {
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
    Mfa.prototype._getPass1 = function (userId, userPin, scope, X, SEC, callback) {
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

        errorCode = self.crypto(curve).MPIN.CLIENT_1(self.crypto(curve).MPIN.SHA256, 0, self._hexToBytes(mpinIdHex), self.rng, X, userPin, self._hexToBytes(tokenHex), SEC, U, UT, self._hexToBytes(0));
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

        self.request({ url: self.options.settings.mpinAuthServerURL + "/pass1", type: "POST", data: requestData }, callback);
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
    Mfa.prototype._getPass2 = function (userId, scope, yHex, X, SEC, callback) {
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
        errorCode = self.crypto(curve).MPIN.CLIENT_2(X, yBytes, SEC);
        if (errorCode !== 0) {
            return callback(new CryptoError("Could not calculate pass 2 request data", errorCode), null);
        }

        requestData = {
            mpin_id: userStorage.get(userId, "mpinId"),
            V: self._bytesToHex(SEC)
        };

        if (scope.indexOf("otp") !== -1) {
            requestData.WID = "0";
        } else {
            requestData.WID = self.accessId;
        }

        self.request({ url: self.options.settings.mpinAuthServerURL + "/pass2", type: "POST", data: requestData}, callback);
    };

    Mfa.prototype._finishAuthentication = function (userId, userPin, scope, authOTT, callback) {
        var self = this,
            requestData,
            userStorage,
            isDvsAuth;

        requestData = {
            "authOTT": authOTT
        };

        isDvsAuth = scope.indexOf("dvs-auth") !== -1;
        userStorage = isDvsAuth ? self.dvsUsers : self.users;

        self.request({ url: self.options.settings.authenticateURL, type: "POST", data: requestData }, function (err, data) {
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

    Mfa.prototype._renewSecret = function (userId, userPin, sec1Data, callback) {
        var self = this;

        self._getSecret2(userId, sec1Data, function (err, sec2Data) {
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

    Mfa.prototype.registerDvs = function (userId, userPin, dvsPin, callback) {
        var self = this;

        self._authentication(userId, userPin, ["dvs-reg"], function (err, data) {
            if (err) {
                return callback(err, null);
            }

            self._renewDvsSecret(userId, dvsPin, data.dvsRegister, callback);
        });
    };

    Mfa.prototype._renewDvsSecret = function (userId, userPin, dvsRegister, callback) {
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

    Mfa.prototype._getDvsSecret1 = function (keypair, dvsRegisterToken, callback) {
        var self = this,
            cs1Url,
            reqData;

        reqData = {
            publicKey: keypair.publicKey,
            deviceName: self._getDeviceName(),
            dvsRegisterToken: dvsRegisterToken
        };

        cs1Url = self.options.settings.dvsRegURL;

        self.request({ url: cs1Url, type: "POST", data: reqData }, callback);
    };

    Mfa.prototype._generateSignKeypair = function (curve) {
        var self = this,
            privateKeyBytes = [],
            publicKeyBytes = [],
            errorCode;

        errorCode = self.crypto(curve).MPIN.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
        if (errorCode != 0) {
            throw new CryptoError("Could not generate key pair", errorCode);
        }

        return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
    };

    Mfa.prototype._createSigningIdentity = function (userId, userPin, sec1Data, sec2Data, keypair, callback) {
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
    Mfa.prototype._generateSignClientSecret = function (privateKeyHex, clientSecretHex, curve) {
        var self = this,
            privateKeyBytes = self._hexToBytes(privateKeyHex),
            clientSecretBytes = self._hexToBytes(clientSecretHex),
            errorCode;

        errorCode = self.crypto(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
        if (errorCode != 0) {
            throw new CryptoError("Could not combine private key with client secret", errorCode);
        }

        return self._bytesToHex(clientSecretBytes);
    };

    Mfa.prototype._getSignMpinId = function (mpinId, publicKey) {
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

    Mfa.prototype.signMessage = function (userId, userPin, message, timestamp, callback) {
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

        errorCode = self.crypto(curve).MPIN.CLIENT(self.crypto(curve).MPIN.SHA256, 0, mpinIdBytes, self.rng, X, userPin, tokenBytes, SEC, U, null, null, timestamp, Y1, messageBytes);
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
    Mfa.prototype._hexToBytes = function (hexValue) {
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

    Mfa.prototype._bytesToHex = function (b) {
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

    /**
     * Make an HTTP request
     * @private
     */
    Mfa.prototype.request = function (options, callback) {
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

        request.open(type, url, true);

        request.setRequestHeader("X-MIRACL-CID", self.options.client.customerId);

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

    /**
     * User management utility. Initialized by {@link Mfa}
     * @class
     *
     * @param {Object} storage
     * @param {string} customerId
     * @param {string} storageKey
     */
    Users = function (storage, customerId, storageKey) {
        var self = this;

        if (typeof storage.getItem !== "function" || typeof storage.setItem !== "function") {
            throw new Error("Invalid user storage object");
        }

        self.storage = storage;
        self.customerId = customerId;
        self.storageKey = storageKey ? storageKey : "mfa";

        self.loadData();
    };

    Users.prototype.data = [],

    Users.prototype.states = {
        invalid: "INVALID",
        start: "STARTED",
        active: "ACTIVATED",
        register: "REGISTERED",
        revoked: "REVOKED"
    };

    Users.prototype.loadData = function () {
        var self = this;

        self.data = JSON.parse(self.storage.getItem(self.storageKey)) || [];

        self.store();

        // Sort list by last used timestamp
        self.data.sort(function (a, b) {
            if (a.lastUsed && (!b.lastUsed || a.lastUsed > b.lastUsed)) {
                return 1;
            }

            if (b.lastUsed && (!a.lastUsed || a.lastUsed < b.lastUsed)) {
                return -1;
            }

            return 0;
        });
    };

    Users.prototype.write = function (userId, userData) {
        var self = this, i, uKey;

        if (!self.exists(userId)) {
            self.data.push({
                userId: userId,
                customerId: self.customerId,
                state: self.states.invalid,
                created: Math.round(new Date().getTime() / 1000)
            });
        }

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].userId === userId && self.data[i].customerId === self.customerId) {
                for (uKey in userData) {
                    if (userData[uKey]) {
                        self.data[i][uKey] = userData[uKey];
                    }
                }
            }
        }

        self.store();
    };

    Users.prototype.updateLastUsed = function (userId) {
        this.write(userId, { lastUsed: new Date().getTime() });
    };

    /**
     * Check if an user with the specified user ID exists
     * @param {string} userId - The ID of the user
     * @returns {boolean}
     */
    Users.prototype.exists = function (userId) {
        return typeof this.get(userId, "userId") !== "undefined";
    };

    /**
     * Check if an user is in a specific state
     * @param {string} userId - The ID of the user
     * @param {string} state - The state to check for
     * @returns {boolean} - Returns true if the state of the user matches the state argument
     */
    Users.prototype.is = function (userId, state) {
        return this.get(userId, "state") === state;
    };

    /**
     * Get a property of the user
     * @param {string} userId - The ID of the user
     * @param {string} userProperty - The name of the property to be fetched
     * @returns {string} - The value of the user property. Will return undefined if property doesn't exist
     */
    Users.prototype.get = function (userId, userProperty) {
        var self = this, i;

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].userId === userId && self.data[i].customerId === self.customerId) {
                if (userProperty) {
                    // Return requested property
                    return self.data[i][userProperty] || "";
                } else {
                    // Return the whole user data if no property is requested
                    return self.data[i];
                }
            }
        }
    };

    /**
     * List all identities
     * @returns {Object}
     */
    Users.prototype.list = function () {
        var self = this, usersList = {}, i;

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].customerId === self.customerId) {
                usersList[self.data[i].userId] = self.data[i].state;
            }
        }

        return usersList;
    };

    /**
     * Remove an identity
     * @param {string} userId - The ID of the user
     */
    Users.prototype.delete = function (userId) {
        var self = this, i;

        if (!self.exists(userId)) {
            return;
        }

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].userId === userId && self.data[i].customerId === self.customerId) {
                self.data.splice(i, 1);
            }
        }

        self.store();
    };

    Users.prototype.store = function () {
        var self = this,
            i;

        // Ensure that there is no sensitive data before storing it
        for (i = 0; i < self.data.length; ++i) {
            delete self.data[i].csHex;
            delete self.data[i].regOTT;
        }

        self.storage.setItem(self.storageKey, JSON.stringify(self.data));
    };

})();

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = Mfa;
}
