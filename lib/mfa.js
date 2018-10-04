var Mfa = Mfa || {};

(function() {
    "use strict";

    var CryptoContexts = {},
        Registration = {},
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

    Mfa = function(options) {
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

        if (!options.seed) {
            throw new Error("Missing random number generator seed");
        }

        // Ensure that default PIN lenght is between 4 and 6
        if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
            options.defaultPinLength = 4;
        }

        self.initializeRNG(options.seed);
        options.seed = "";
        delete options.seed;

        self.users = new Users(options.customerId);
        self.dvsUsers = new Users(options.customerId, "dvs");

        self.options = {};
        self.options.client = options;
    };

    Mfa.prototype.options = {};

    Mfa.prototype.ctx = function (curve) {
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
     * Initialize the Random Number Generator (RNG)
     */
    Mfa.prototype.initializeRNG = function (seedHex) {
        var self = this,
            entropyBytes;

        entropyBytes = self._hexToBytes(seedHex);

        self.rng = new (self.ctx().RAND)();
        self.rng.clean();
        self.rng.seed(entropyBytes.length, entropyBytes);
    };

    Mfa.prototype.init = function(successCb, errorCb) {
        var self = this, settingsUrl;

        settingsUrl = self.options.client.server.replace(/\/?$/, "/");
        settingsUrl += "rps/v2/clientSettings";

        if (self.options.client.clientId) {
            settingsUrl += "?cid=" + self.options.client.clientId;
        }

        self.request({ url: settingsUrl }, function(err, settingsData) {
            if (err) {
                return errorCb(err);
            }
            self.options.settings = settingsData;

            successCb(true);
        });
    };

    Mfa.prototype.setAccessId = function (accessId) {
        this.accessId = accessId;
    };

    Mfa.prototype.register = function (userId, registrationCode, pinCb, confirmCb, successCb, errorCb) {
        var self = this,
            confirm,
            passPin;

        // should be called to continue the registration
        // flow after the email was confirmed
        confirm = function () {
            self.confirmRegistration(userId, function () {
                var pinLength;

                pinLength = self.users.get(userId, "pinLength");
                if (!pinLength) {
                    pinLength = self.options.client.defaultPinLength;
                }

                pinCb(passPin, pinLength);
            }, errorCb);
        };

        // should be called to continue the flow
        // after a PIN was provided
        passPin = function (userPin) {
            self.finishRegistration(userId, userPin, successCb, errorCb);
        };

        self.init(function () {
            self.startRegistration(userId, registrationCode, function () {
                if (registrationCode) {
                    confirm();
                } else {
                    confirmCb(confirm);
                }
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype.startRegistration = function(userId, registrationCode, successCb, errorCb) {
        var self = this;

        if (!userId) {
            throw new Error("Missing user ID");
        }

        self._registration(userId, registrationCode, function(err) {
            if (err) {
                if (registrationCode && err.status === 403) {
                    return errorCb(new InvalidRegCodeError("Invalid registration code"));
                } else {
                    return errorCb(err);
                }
            }
            successCb(true);
        });
    };

    Mfa.prototype._registration = function(userId, registrationCode, cb) {
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

        self.request(regData, function(err, data) {
            if (err) {
                return cb(err, null);
            }

            Registration.regOTT = data.regOTT;
            data.regOTT = "";
            delete data.regOTT;

            data.state = (data.active) ? self.users.states.active : self.users.states.start;
            self.users.write(userId, data);

            cb(null, data);
        });
    };

    Mfa.prototype._getDeviceName = function () {
        var self = this;

        if (self.options.client.deviceName) {
            return self.options.client.deviceName;
        }

        return "Browser";
    };

    Mfa.prototype.confirmRegistration = function(userId, successCb, errorCb) {
        var self = this;

        if (!userId) {
            throw new Error("Missing user ID");
        }

        if (!self.users.is(userId, self.users.states.start) && !self.users.is(userId, self.users.states.active)) {
            return errorCb(new IdentityError("Identity is not in suitable state"));
        }

        self._getSecret(userId, function(err) {
            if (err) {
                if (err.status === 401) {
                    return errorCb(new NotVerifiedError("Identity not verified"));
                } else if (err.status === 404) {
                    return errorCb(new VerificationExpiredError("Registration session expired"));
                } else {
                    return errorCb(err);
                }
            }

            successCb(true);
        });
    };

    Mfa.prototype._getSecret = function(userId, cb) {
        var self = this;

        self._getSecret1(userId, function(err, sec1Data) {
            if (err) {
                return cb(err, null);
            }

            self._getSecret2(userId, sec1Data, cb);
        });
    };

    Mfa.prototype._getSecret1 = function(userId, cb) {
        var self = this, cs1Url;

        cs1Url = self.options.settings.signatureURL + "/";
        cs1Url += self.users.get(userId, "mpinId");
        cs1Url += "?regOTT=" + Registration.regOTT;

        self.request({ url: cs1Url }, function(err, data) {
            if (err) {
                return cb(err, null);
            }

            cb(null, data);
        });
    };

    Mfa.prototype._getSecret2 = function(userId, sec1Data, cb) {
        var self = this;

        self.request({ url: sec1Data.cs2url }, function(err, sec2Data) {
            var userData;

            if (err) {
                return cb(err, null);
            }

            // Remove registration OTT
            Registration.regOTT = "";
            delete Registration.regOTT;

            try {
                Registration.csHex = self._addShares(sec1Data.clientSecretShare, sec2Data.clientSecret, sec1Data.curve);
            } catch (err) {
                return cb(err, null);
            }

            userData = {
                state: self.users.states.active,
                dtas: sec1Data.dtas,
                curve: sec1Data.curve
            };

            self.users.write(userId, userData);
            cb(null, true);
        });
    };

    /**
     * Add two points on the curve that are originally in hex format
     * This function is used to add client secret shares.
     * Returns a hex encoded sum of the shares
     */
    Mfa.prototype._addShares = function (share1Hex, share2Hex, curve) {
        var self = this,
            share1Bytes = [],
            share2Bytes = [],
            sumBytes = [],
            errorCode;

        share1Bytes = self._hexToBytes(share1Hex);
        share2Bytes = self._hexToBytes(share2Hex);

        errorCode = self.ctx(curve).MPIN.RECOMBINE_G1(share1Bytes, share2Bytes, sumBytes);
        if (errorCode !== 0) {
            throw new CryptoError("Could not combine the client secret shares", errorCode);
        }

        return self._bytesToHex(sumBytes);
    };

    Mfa.prototype.finishRegistration = function(userId, userPin, successCb, errorCb) {
        var self = this, userData, token;

        if (!userId) {
            throw new Error("Missing user ID");
        }

        if (!self.users.is(userId, self.users.states.active)) {
            return errorCb(new IdentityError("Identity is not in suitable state"));
        }

        try {
            token = self._calculateMPinToken(self.users.get(userId, "mpinId"), userPin, Registration.csHex, self.users.get(userId, "curve"));
        } catch (err) {
            return errorCb(err);
        }

        // Remove the client secret
        Registration.csHex = "";
        delete Registration.csHex;

        userData = {
            token: token,
            state: self.users.states.register
        };
        self.users.write(userId, userData);

        successCb(userData);
    };

    /**
     * Calculates the MPin Token
     * This function maps the M-Pin ID to a point on the curve,
     * multiplies this value by PIN and then subtractsit from
     * the client secret curve point to generate the M-Pin token.
     * Returns a hex encoded M-Pin Token
     */
    Mfa.prototype._calculateMPinToken = function (mpinIdHex, PIN, clientSecretHex, curve) {
        var self = this,
            clientSecretBytes = [],
            mpinIdBytes = [],
            errorCode;

        clientSecretBytes = self._hexToBytes(clientSecretHex);
        mpinIdBytes = self._hexToBytes(mpinIdHex);

        errorCode = self.ctx(curve).MPIN.EXTRACT_PIN(self.ctx(curve).MPIN.HASH_TYPE, mpinIdBytes, PIN, clientSecretBytes);
        if (errorCode !== 0) {
            throw new CryptoError("Could not extract PIN from client secret", errorCode);
        }

        return self._bytesToHex(clientSecretBytes);
    };

    Mfa.prototype._authentication = function (userId, userPin, scope, successCb, errorCb) {
        var self = this,
            userStorage;

        userStorage = scope.indexOf("dvs-auth") !== -1 ? self.dvsUsers : self.users;

        if (!userStorage.exists(userId)) {
            return errorCb(new IdentityError("Missing identity"));
        }

        self.init(function () {
            self.startAuthentication(userId, userPin, scope, function (passData) {
                self.finishAuthentication(userId, userPin, scope, passData.authOTT, successCb, errorCb);
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype.authenticate = function (userId, userPin, successCb, errorCb) {
        this._authentication(userId, userPin, ["oidc"], successCb, errorCb);
    };

    Mfa.prototype.fetchOTP = function (userId, userPin, successCb, errorCb) {
        this._authentication(userId, userPin, ["otp"], successCb, errorCb);
    };

    Mfa.prototype.fetchRegistrationCode = function (userId, userPin, successCb, errorCb) {
        this._authentication(userId, userPin, ["reg-code"], successCb, errorCb);
    };

    Mfa.prototype.startAuthentication = function (userId, userPin, scope, successCb, errorCb) {
        var self = this;

        self._getPass(userId, userPin, scope, function (err, data) {
            if (err) {
                return errorCb(err);
            }
            successCb(data);
        });
    };

    Mfa.prototype._getPass = function (userId, userPin, scope, callback) {
        var self = this,
            X = [],
            SEC = [];

        self._getPass1(userId, userPin, scope, X, SEC, function (err, pass1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getPass2(userId, scope, pass1Data.y, X, SEC, callback);
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

        errorCode = self.ctx(curve).MPIN.CLIENT_1(self.ctx(curve).MPIN.HASH_TYPE, 0, self._hexToBytes(mpinIdHex), self.rng, X, userPin, self._hexToBytes(tokenHex), SEC, U, UT, self._hexToBytes(0));
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
        errorCode = self.ctx(curve).MPIN.CLIENT_2(X, yBytes, SEC);
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

    Mfa.prototype.finishAuthentication = function (userId, userPin, scope, authOTT, successCb, errorCb) {
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

                return errorCb(err);
            }

            if (data.renewSecret) {
                self._renewSecret(userId, userPin, data.renewSecret, successCb, errorCb);
            } else if (data.dvsRegister && isDvsAuth) {
                // Renew automatically only if signing
                self._renewDvsSecret(userId, userPin, data.dvsRegister, successCb, errorCb);
            } else {
                self.users.updateLastUsed(userId);
                successCb(data);
            }
        });
    };

    Mfa.prototype._renewSecret = function (userId, userPin, sec1Data, successCb, errorCb) {
        var self = this;

        self.request({ url: sec1Data.cs2url }, function(err, sec2Data) {
            var csHex,
                token;

            if (err) {
                return errorCb(err);
            }

            try {
                csHex = self._addShares(sec1Data.clientSecretShare, sec2Data.clientSecret, sec1Data.curve);
                token = self._calculateMPinToken(sec1Data.mpin_id, userPin, csHex, sec1Data.curve);

                // Write to user storage
                self.users.write(userId, {
                    token: token,
                    mpinId: sec1Data.mpin_id,
                    dtas: sec1Data.dtas,
                    curve: sec1Data.curve,
                    state: self.users.states.register
                });
            } catch (err) {
                return errorCb(err);
            }

            self.authenticate(userId, userPin, successCb, errorCb);
        });
    };

    Mfa.prototype.registerDvs = function (userId, userPin, dvsPin, successCb, errorCb) {
        var self = this;

        self._authentication(userId, userPin, ["dvs-reg"], function (data) {
            self._renewDvsSecret(userId, dvsPin, data.dvsRegister, successCb, errorCb);
        }, errorCb);
    };

    Mfa.prototype._renewDvsSecret = function (userId, userPin, dvsRegister, successCb, errorCb) {
        var self = this,
            keypair;

        keypair = self.generateSignKeypair(dvsRegister.curve);

        self._getDvsSecret1(keypair, dvsRegister.token, function (cs1Data) {
            self._getDvsSecret2(cs1Data, function (cs2Data) {
                try {
                    self.createSigningIdentity(userId, userPin, cs1Data, cs2Data, keypair);
                } catch (err) {
                    return errorCb(err);
                }

                successCb();
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype._getDvsSecret1 = function (keypair, dvsRegisterToken, successCb, errorCb) {
        var self = this,
            cs1Url,
            reqData;

        reqData = {
            publicKey: keypair.publicKey,
            deviceName: self._getDeviceName(),
            dvsRegisterToken: dvsRegisterToken
        };

        cs1Url = self.options.settings.dvsRegURL;

        self.request({ url: cs1Url, type: "POST", data: reqData }, function(err, cs1Data) {
            if (err) {
                return errorCb(err);
            }

            successCb(cs1Data);
        });
    };

    Mfa.prototype._getDvsSecret2 = function (cs1Data, successCb, errorCb) {
        var self = this;

        self.request({ url: cs1Data.cs2url }, function(err, cs2Data) {
            if (err) {
                return errorCb(err);
            }

            successCb(cs2Data);
        });
    };

    Mfa.prototype.generateSignKeypair = function (curve) {
        var self = this,
            privateKeyBytes = [],
            publicKeyBytes = [],
            errorCode;

        errorCode = self.ctx(curve).MPIN.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
        if (errorCode != 0) {
            throw new CryptoError("Could not generate key pair", errorCode);
        }

        return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
    };

    Mfa.prototype.createSigningIdentity = function (userId, pinValue, cs1Data, cs2Data, keypair) {
        var self = this,
            csHex,
            token,
            signMpinId;

        csHex = self._addShares(cs1Data.dvsClientSecretShare, cs2Data.dvsClientSecret, cs1Data.curve);
        csHex = self._generateSignClientSecret(keypair.privateKey, csHex, cs1Data.curve);

        signMpinId = self._getSignMpinId(cs1Data.mpinId, keypair.publicKey);
        token = self._calculateMPinToken(signMpinId, pinValue, csHex, cs1Data.curve);

        self.dvsUsers.write(userId, {
            mpinId: cs1Data.mpinId,
            dtas: cs1Data.dtas,
            curve: cs1Data.curve,
            publicKey: keypair.publicKey,
            token: token,
            state: self.dvsUsers.states.register
        });
    };

    /**
     * Compute client secret for key escrow less scheme
     */
    Mfa.prototype._generateSignClientSecret = function (privateKeyHex, clientSecretHex, curve) {
        var self = this,
            privateKeyBytes = self._hexToBytes(privateKeyHex),
            clientSecretBytes = self._hexToBytes(clientSecretHex),
            errorCode;

        errorCode = self.ctx(curve).MPIN.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
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

        for (i = 0; i < publicKeyBytes.length; i++) {
            mpinIdBytes.push(publicKeyBytes[i]);
        }

        return self._bytesToHex(mpinIdBytes);
    };

    Mfa.prototype.signMessage = function (userId, userPin, message, timestamp, successCb, errorCb) {
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

        errorCode = self.ctx(curve).MPIN.CLIENT(self.ctx(curve).MPIN.HASH_TYPE, 0, mpinIdBytes, self.rng, X, userPin, tokenBytes, SEC, U, null, null, timestamp, Y1, messageBytes);
        if (errorCode != 0) {
            errorCb(new CryptoError("Could not sign message", errorCode));
        }

        signatureData = {
            hash: message,
            u: self._bytesToHex(U),
            v: self._bytesToHex(SEC),
            mpinId: self.dvsUsers.get(userId, "mpinId"),
            publicKey: self.dvsUsers.get(userId, "publicKey"),
            dtas: self.dvsUsers.get(userId, "dtas")
        };

        this._authentication(userId, userPin, ["dvs-auth"], function () {
            successCb(signatureData);
        }, errorCb);
    };

    /**
     * Convert a hex representation of a Point to a bytes array
     */
    Mfa.prototype._hexToBytes = function (hexValue) {
        var len, byteValue, i;

        len = hexValue.length;
        byteValue = [];

        for (i = 0; i < len; i += 2) {
            byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
        }

        return byteValue;
    };

    Mfa.prototype._bytesToHex = function(b) {
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
     * USER MANAGEMENT
     */
    Users = function (customerId, storageKey) {
        var self = this;

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

        self.data = JSON.parse(localStorage.getItem(self.storageKey)) || [];

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

    Users.prototype.write = function(userId, userData) {
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

    Users.prototype.exists = function(userId) {
        return (this.get(userId, "userId") !== false);
    };

    Users.prototype.is = function (userId, state) {
        return this.get(userId, "state") === state;
    };

    Users.prototype.get = function(userId, userProperty) {
        var self = this, i;

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].userId === userId && self.data[i].customerId === self.customerId) {
                return self.data[i][userProperty] || "";
            }
        }

        return false;
    };

    Users.prototype.list = function() {
        var self = this, usersList = {}, i;

        for (i = 0; i < self.data.length; ++i) {
            if (self.data[i].customerId === self.customerId) {
                usersList[self.data[i].userId] = self.data[i].state;
            }
        }

        return usersList;
    };

    Users.prototype.delete = function(userId) {
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

    Users.prototype.store = function() {
        var self = this,
            i;

        // Ensure that there is no sensitive data before storing it
        for (i = 0; i < self.data.length; ++i) {
            delete self.data[i].csHex;
            delete self.data[i].regOTT;
        }

        localStorage.setItem(self.storageKey, JSON.stringify(self.data));
    };

})();

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = Mfa;
}
