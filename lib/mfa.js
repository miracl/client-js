var Mfa = Mfa || {};

(function() {
    "use strict";

    var Registration = {},
        RequestError = createErrorType("RequestError", ["message", "status"]),
        CryptoError = createErrorType("CryptoError", ["message", "code"]),
        NotVerifiedError = createErrorType("NotVerifiedError", ["message"]),
        VerificationExpiredError = createErrorType("VerificationExpiredError", ["message"]),
        IdentityError = createErrorType("IdentityError", ["message"]),
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

        self.ctx = new CTX("BN254CX");

        self.mpin = self.ctx.MPIN;

        // Change maximum PIN length to 6 digits
        self.mpin.MAXPIN = 1000000;
        self.mpin.PBLEN = 20;
        self.mpin.TRAP = 2000;

        // Ensure that default PIN lenght is between 4 and 6
        if (!options.defaultPinLength || options.defaultPinLength > 6 || options.defaultPinLength < 4) {
            options.defaultPinLength = 4;
        }

        self.initializeRNG(options.seed);
        options.seed = "";
        delete options.seed;

        self.users = new Users(options.customerId);

        self.options = {};
        self.options.client = options;
    };

    Mfa.prototype.options = {};

    /**
     * Initialize the Random Number Generator (RNG)
     */
    Mfa.prototype.initializeRNG = function (seedHex) {
        var self = this,
            entropyBytes;

        entropyBytes = self._hexToBytes(seedHex);

        self.rng = new self.ctx.RAND();
        self.rng.clean();
        self.rng.seed(entropyBytes.length, entropyBytes);
    };

    Mfa.prototype.init = function(successCb, errorCb) {
        var self = this, settingsUrl;

        settingsUrl = self.options.client.server.replace(/\/?$/, "/");
        settingsUrl += "rps/clientSettings";

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
                return errorCb(err);
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
        var self = this,
            cs2Url;

        cs2Url = self.options.settings.certivoxURL;
        cs2Url += "clientSecret?";
        cs2Url += sec1Data.params;

        self.request({ url: cs2Url }, function(err, sec2Data) {
            var userData;

            if (err) {
                return cb(err, null);
            }

            // Remove registration OTT
            Registration.regOTT = "";
            delete Registration.regOTT;

            try {
                Registration.csHex = self._addShares(sec1Data.clientSecretShare, sec2Data.clientSecret);
            } catch (err) {
                return cb(err, null);
            }

            userData = {
                state: self.users.states.active
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
    Mfa.prototype._addShares = function (share1Hex, share2Hex) {
        var self = this,
            share1Bytes = [],
            share2Bytes = [],
            sumBytes = [],
            errorCode;

        share1Bytes = self._hexToBytes(share1Hex);
        share2Bytes = self._hexToBytes(share2Hex);

        errorCode = self.mpin.RECOMBINE_G1(share1Bytes, share2Bytes, sumBytes);
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
            token = self._calculateMPinToken(self.users.get(userId, "mpinId"), userPin, Registration.csHex);
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
    Mfa.prototype._calculateMPinToken = function (mpinIdHex, PIN, clientSecretHex) {
        var self = this,
            clientSecretBytes = [],
            mpinIdBytes = [],
            errorCode;

        clientSecretBytes = self._hexToBytes(clientSecretHex);
        mpinIdBytes = self._hexToBytes(mpinIdHex);

        errorCode = self.mpin.EXTRACT_PIN(self.mpin.HASH_TYPE, mpinIdBytes, PIN, clientSecretBytes);
        if (errorCode !== 0) {
            throw new CryptoError("Could not extract PIN from client secret", errorCode);
        }

        return self._bytesToHex(clientSecretBytes);
    };

    Mfa.prototype.authenticate = function (userId, userPin, successCb, errorCb) {
        var self = this;

        if (!self.users.exists(userId)) {
            return errorCb(new IdentityError("Missing identity"));
        }

        self.init(function () {
            self.startAuthentication(userId, userPin, function (data) {
                self.finishAuthentication(userId, userPin, data.authOTT, successCb, errorCb);
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype._getOTP = function (userId, userPin, OTPUse, successCb, errorCb) {
        var self = this;

        if (!self.users.exists(userId)) {
            return errorCb(new IdentityError("Missing identity"));
        }

        self.init(function () {
            self._getPass(userId, userPin, OTPUse, function (err, data) {
                var requestData,
                    otp;

                if (err) {
                    return errorCb(err);
                }

                requestData = {
                    "mpinResponse": {
                        "authOTT": data.authOTT
                    }
                };

                otp = data.OTP;

                self.request({ url: self.options.settings.authenticateURL, type: "POST", data: requestData }, function (err, data) {
                    if (err) {
                        // Revoked identity
                        if (err.status === 410) {
                            self.users.write(userId, { state: self.users.states.revoked });
                        }

                        return errorCb(err);
                    }

                    data.otp = otp;
                    self.users.updateLastUsed(userId);

                    successCb(data);
                });
            });
        }, errorCb);
    };

    Mfa.prototype.fetchOTP = function (userId, userPin, successCb, errorCb) {
        this._getOTP(userId, userPin, "authentication", successCb, errorCb);
    };

    Mfa.prototype.fetchRegistrationCode = function (userId, userPin, successCb, errorCb) {
        this._getOTP(userId, userPin, "registration", successCb, errorCb);
    };

    Mfa.prototype.startAuthentication = function (userId, userPin, successCb, errorCb) {
        var self = this;

        self._getPass(userId, userPin, false, function (err, data) {
            if (err) {
                return errorCb(err);
            }
            successCb(data);
        });
    };

    Mfa.prototype._getPass = function (userId, userPin, OTP, callback) {
        var self = this,
            X = [],
            SEC = [];

        self._getPass1(userId, userPin, X, SEC, function (err, pass1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getPass2(userId, pass1Data.y, X, SEC, OTP, callback);
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
     *    mpin_id: mpinIdHex, // Hex encoded M-Pin ID
     *    UT: UT_hex, // Hex encoded UT
     *    U: U_hex, // Hex encoded U
     *    pass: 1 // Protocol first pass
     * }
     */
    Mfa.prototype._getPass1 = function (userId, userPin, X, SEC, callback) {
        var self = this,
            mpinIdHex = self.users.get(userId, "mpinId"),
            tokenHex = self.users.get(userId, "token"),
            mpinIdBytes = self._hexToBytes(mpinIdHex),
            tokenBytes = self._hexToBytes(tokenHex),
            timePermitBytes = self._hexToBytes(0),
            U = [],
            UT = [],
            errorCode,
            requestData;

        errorCode = self.mpin.CLIENT_1(self.mpin.HASH_TYPE, 0, mpinIdBytes, self.rng, X, userPin, tokenBytes, SEC, U, UT, timePermitBytes);
        if (errorCode !== 0) {
            return callback(new CryptoError("Could not calculate pass 1 request data", errorCode), null);
        }

        requestData = {
            mpin_id: mpinIdHex,
            UT: self._bytesToHex(UT),
            U: self._bytesToHex(U),
            pass: 1
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
     *    V: V_hex, // Value required by the server to authenticate user
     *    OTP: bool(OTP), // Whether to request OTP
     *    OTPUse: OTP, // What the OTP will be used for (registration, authentication)
     *    WID: accessNumber, // Number required for mobile authentication
     *    pass: 2 // Protocol second pass
     * }
     */
    Mfa.prototype._getPass2 = function (userId, yHex, X, SEC, OTP, callback) {
        var self = this,
            mpinIdHex = self.users.get(userId, "mpinId"),
            requestData,
            yBytes,
            errorCode;

        yBytes = self._hexToBytes(yHex);

        // Compute V
        errorCode = self.mpin.CLIENT_2(X, yBytes, SEC);
        if (errorCode !== 0) {
            return callback(new CryptoError("Could not calculate pass 2 request data", errorCode), null);
        }

        requestData = {
            mpin_id: mpinIdHex,
            V: self._bytesToHex(SEC),
            pass: 2
        };

        if (!OTP) {
            requestData.WID = self.accessId;
        } else {
            requestData.WID = "0";
            requestData.OTP = true;
            requestData.OTPUse = OTP;
        }

        self.request({ url: self.options.settings.mpinAuthServerURL + "/pass2", type: "POST", data: requestData}, callback);
    };

    Mfa.prototype.finishAuthentication = function (userId, userPin, authOTT, successCb, errorCb) {
        var self = this, requestData;

        requestData = {
            "mpinResponse": {
                "authOTT": authOTT
            }
        };

        self.request({ url: self.options.settings.authenticateURL, type: "POST", data: requestData }, function (err, data) {
            if (err) {
                // Revoked identity
                if (err.status === 410) {
                    self.users.write(userId, { state: self.users.states.revoked });
                }

                return errorCb(err);
            }

            self.users.updateLastUsed(userId);

            successCb(data);
        });
    };

    Mfa.prototype.registerDvs = function (userId, accessToken, pinCb, successCb, errorCb) {
        var self = this,
            keypair;

        keypair = self.generateSignKeypair();

        self.init(function () {
            self._getDvsSecret1(keypair, accessToken, function (cs1Data) {
                self._getDvsSecret2(cs1Data, function (cs2Data) {
                    pinCb(function (userPin) {
                        try {
                            self.createSigningIdentity(userId, cs1Data["mpinId"], cs1Data["dvsClientSecretShare"], cs2Data["dvsClientSecret"], keypair, userPin);
                        } catch (err) {
                            return errorCb(err);
                        }

                        successCb();
                    });
                }, errorCb);
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype._getDvsSecret1 = function (keypair, accessToken, successCb, errorCb) {
        var self = this,
            cs1Url,
            reqData,
            authHeader;

        reqData = {
            publicKey: keypair.publicKey,
            deviceName: self._getDeviceName()
        };

        cs1Url = self.options.settings.dvsRegURL;
        if (self.options.client.clientId) {
            cs1Url += "?cid=" + self.options.client.clientId;
        }

        authHeader = "Bearer " + accessToken;

        self.request({ url: cs1Url, type: "POST", authorization: authHeader, data: reqData }, function(err, cs1Data) {
            if (err) {
                return errorCb(err);
            }

            successCb(cs1Data);
        });
    };

    Mfa.prototype._getDvsSecret2 = function (cs1Data, successCb, errorCb) {
        var self = this,
            cs2Url;

        cs2Url = self.options.settings.certivoxURL;
        cs2Url += "clientSecret?";
        cs2Url += cs1Data["params"];

        self.request({ url: cs2Url }, function(err, cs2Data) {
            if (err) {
                return errorCb(err);
            }

            successCb(cs2Data);
        });
    };

    Mfa.prototype.generateSignKeypair = function () {
        var self = this,
            privateKeyBytes = [],
            publicKeyBytes = [],
            errorCode;

        errorCode = self.mpin.GET_DVS_KEYPAIR(self.rng, privateKeyBytes, publicKeyBytes);
        if (errorCode != 0) {
            throw new CryptoError("Could not generate key pair", errorCode);
        }

        return { publicKey: self._bytesToHex(publicKeyBytes), privateKey: self._bytesToHex(privateKeyBytes) };
    };

    Mfa.prototype.createSigningIdentity = function (userId, mpinId, share1Hex, share2Hex, keypair, pinValue) {
        var self = this,
            csHex,
            token,
            signMpinId;

        csHex = self._addShares(share1Hex, share2Hex);
        csHex = self._generateSignClientSecret(keypair.privateKey, csHex);

        signMpinId = self._getSignMpinId(mpinId, keypair.publicKey);
        token = self._calculateMPinToken(signMpinId, pinValue, csHex);

        self.users.write(userId, {
            mpinId: mpinId,
            publicKey: keypair.publicKey,
            token: token,
            state: self.users.states.register
        });
    };

    /**
     * Compute client secret for key escrow less scheme
     */
    Mfa.prototype._generateSignClientSecret = function (privateKeyHex, clientSecretHex) {
        var self = this,
            privateKeyBytes = self._hexToBytes(privateKeyHex),
            clientSecretBytes = self._hexToBytes(clientSecretHex),
            errorCode;

        errorCode = self.mpin.GET_G1_MULTIPLE(null, 0, privateKeyBytes, clientSecretBytes, clientSecretBytes);
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

    Mfa.prototype.signMessage = function (userId, userPin, message, timestamp) {
        var self = this,
            messageBytes = self._hexToBytes(message),
            mpinIdHex = self._getSignMpinId(self.users.get(userId, "mpinId"), self.users.get(userId, "publicKey")),
            mpinIdBytes = self._hexToBytes(mpinIdHex),
            tokenHex = self.users.get(userId, "token"),
            tokenBytes = self._hexToBytes(tokenHex),
            SEC = [],
            X = [],
            Y1 = [],
            U = [],
            errorCode;

        errorCode = self.mpin.CLIENT(self.mpin.HASH_TYPE, 0, mpinIdBytes, self.rng, X, userPin, tokenBytes, SEC, U, null, null, timestamp, Y1, messageBytes);
        if (errorCode != 0) {
            throw new CryptoError("Could not sign message", errorCode);
        }

        return { U: self._bytesToHex(U), V: self._bytesToHex(SEC) };
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
    Users = function (customerId) {
        var self = this;

        self.customerId = customerId;
        self.loadData();
    };

    Users.prototype.storageKey = "mfa";

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
                state: self.states.invalid
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
