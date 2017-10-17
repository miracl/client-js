var Mfa = Mfa || {};

(function() {
    "use strict";

    var Errors = {},
        Registration = {},
        DebugMessages = {},
        Users;

    // Error definitions
    Errors.missingServer = { code: "MISSING_SERVER", description: "Missing server parameter" };
    Errors.missingCustomerId = { code: "MISSING_CUSTOMER_ID", description: "Missing customer ID" };
    Errors.missingCallback = { code: "MISSING_CALLBACK", description: "Bad or missing callback" };
    Errors.identityNotVerified = { code: "IDENTITY_NOT_VERIFIED", description: "Identity not verified" };
    Errors.missingUserId = { code: "MISSING_USERID", description: "Missing user id" };
    Errors.wrongFlow = { code: "WRONG_FLOW", description: "Identity is not in suitable state" };

    DebugMessages.construct = "Mfa library successful initialize";

    DebugMessages.init = {
        info: "Call Init method - get server settings",
        url: "Get URL: ",
        error: "Problem occur, when trying to get server settings",
        ok: "Server settings OK",
    };

    DebugMessages.start = {
        info: "Call Start registration",
        url: "Put URL: ",
        error: "Problem occur, when trying to make user",
        ok: "Create user OK"
    };

    DebugMessages.confirm = {
        info: "Call Confirm registration",
        url: "Get URL: ",
        error: "Problem occur, when trying to make user",
        ok: "Create user OK"
    };

    Mfa = function(options) {
        if (!options || !options.server) {
            throw Errors.missingServer;
        } else if (!options.customerId) {
            throw Errors.missingCustomerId;
        }

        if (!options.seed) {
            throw new Error("Missing random number generator seed");
        }

        this.options = {};
        this.options.client = options;
        this.log(DebugMessages.construct);

        this.users = new Users(options.customerId);

        this.ctx = new CTX("BN254CX");

        this.mpin = this.ctx.MPIN;

        this.initializeRNG(options.seed);
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
        var self = this;

        this.log(DebugMessages.init.info)._getSettings(function(err) {
            if (err) {
                self.log(DebugMessages.init.error, true);
                return errorCb(err);
            }
            self.log(DebugMessages.init.ok);
            successCb(true);
        });
    };

    Mfa.prototype.setAccessId = function (accessId) {
        this.accessId = accessId;
    };

    Mfa.prototype.register = function (userId, pinCb, confirmCb, successCb, errorCb) {
        var self = this,
            confirm,
            passPin;

        // should be called to continue the registration
        // flow after the email was confirmed
        confirm = function () {
            self.confirmRegistration(userId, function () {
                pinCb(passPin);
            }, errorCb);
        };

        // should be called to continue the flow
        // after a PIN was provided
        passPin = function (userPin) {
            self.finishRegistration(userId, userPin, successCb, errorCb);
        };

        self.init(function () {
            self.startRegistration(userId, function () {
                confirmCb(confirm);
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype.startRegistration = function(userId, successCb, errorCb) {
        var self = this;

        if (!userId) {
            return errorCb(Errors.missingUserId);
        } else if (!this.users.suitableFor(userId, "start")) {
            return errorCb(Errors.wrongFlow);
        }

        this.log(DebugMessages.start.start)._registration(userId, function(err) {
            if (err) {
                self.log(DebugMessages.start.error, true);
                return errorCb(err);
            }
            self.log(DebugMessages.start.ok);
            successCb(true);
        });
    };

    Mfa.prototype.confirmRegistration = function(userId, successCb, errorCb) {
        if (!userId) {
            return errorCb(Errors.missingUserId);
        } else if (!this.users.suitableFor(userId, "confirm")) {
            return errorCb(Errors.wrongFlow);
        }

        this._getSecret(userId, function(err) {
            if (err) {
                if (err.status === 401) {
                    return errorCb(Errors.identityNotVerified);
                } else {
                    return errorCb(err);
                }
            }

            successCb(true);
        });
    };

    Mfa.prototype.finishRegistration = function(userId, userPin, successCb, errorCb) {
        var userData, token;

        if (!userId) {
            return errorCb(Errors.missingUserId);
        } else if (!this.users.suitableFor(userId, "finish")) {
            return errorCb(Errors.wrongFlow);
        }

        if (isNaN(userPin)) {
            userPin = this.toHash(userPin);
        }

        token = this._calculateMPinToken(this.users.get(userId, "mpinId"), userPin, Registration.csHex);

        // Remove the client secret
        Registration.csHex = "";
        delete Registration.csHex;

        userData = {
            token: token,
            state: this.users.states.register
        };
        this.users.add(userId, userData);

        successCb(userData);
    };

    Mfa.prototype.toHash = function(strData) {
        var hash = 0,
            i;

        for (i = 0; i < strData.length; i++) {
            hash = ((hash << 5) - hash) + strData.charCodeAt(i);
        }

        return hash;
    };

    Mfa.prototype._registration = function(userId, cb) {
        var self = this,
            regData = {};

        regData.url = this._getUrl({ url: "register" });
        regData.type = "PUT";
        regData.data = {
            userId: userId,
            wid: self.accessId,
            mobile: 0,
            deviceName: self._getDeviceName()
        };

        this.request(regData, function(err, data) {
            if (err) {
                return cb(err, null);
            }

            Registration.regOTT = data.regOTT;
            data.regOTT = "";
            delete data.regOTT;

            data.state = (data.active) ? self.users.states.active : self.users.states.start;
            self.users.add(userId, data);

            cb(null, data);
        });
    };

    Mfa.prototype._getSecret = function(userId, cb) {
        var self = this;

        this._getSecret1(userId, function(err, sec1Data) {
            if (err) {
                return cb(err, null);
            }

            self._getSecret2(userId, sec1Data, cb);
        });
    };

    Mfa.prototype._getSecret1 = function(userId, cb) {
        var cs1Url;

        cs1Url = this._getUrl({ url: "signature", userId: userId });

        this.request({ url: cs1Url }, function(err, data) {
            if (err) {
                return cb(err, null);
            }

            cb(null, data);
        });
    };

    Mfa.prototype._getSecret2 = function(userId, sec1Data, cb) {
        var self = this,
            cs2Url;

        cs2Url = this.options.settings.certivoxURL;
        cs2Url += "clientSecret?";
        cs2Url += sec1Data.params;

        this.request({ url: cs2Url }, function(err, sec2Data) {
            var userData;

            if (err) {
                return cb(err, null);
            }

            // Remove registration OTT
            Registration.regOTT = "";
            delete Registration.regOTT;

            Registration.csHex = self._addShares(sec1Data.clientSecretShare, sec2Data.clientSecret);

            userData = {
                state: self.users.states.active
            };

            self.users.add(userId, userData);
            cb(null, true);
        });
    };

    Mfa.prototype._getDeviceName = function () {
        if (this.options.client.deviceName) {
            return this.options.client.deviceName;
        }

        return "Browser";
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
            return false;
        }

        return self._bytesToHex(sumBytes);
    };

    Mfa.prototype.finishRegistration = function(userId, userPin, successCb, errorCb) {
        var self = this, userData, token;

        if (!userId) {
            return errorCb({ code: "MISSING_USERID", description: "Missing user id" });
        } else if (!self.users.suitableFor(userId, "finish")) {
            return errorCb({ code: "WRONG_FLOW", description: "Identity is not in suitable state" });
        }

        token = self._calculateMPinToken(self.users.get(userId, "mpinId"), userPin, Registration.csHex);
        if (token === false) {
            return errorCb({ code: "EXTRACT_PIN_ERROR", description: "Could not extract PIN from client secret" });
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
            return false;
        }

        return self._bytesToHex(clientSecretBytes);
    };

    Mfa.prototype.authenticate = function (userId, userPin, successCb, errorCb) {
        var self = this;

        if (!this.users.exists(userId)) {
            return errorCb(Errors.missingUserId);
        }

        self.init(function () {
            self.startAuthentication(userId, userPin, function (data) {
                self.finishAuthentication(userId, data.authOTT, successCb, errorCb);
            }, errorCb);
        }, errorCb);
    };

    Mfa.prototype.fetchOTP = function (userId, userPin, successCb, errorCb) {
        var self = this;

        if (!this.users.exists(userId)) {
            return errorCb(Errors.missingUserId);
        }

        self.init(function () {
            self._getPass(userId, userPin, true, function (err, data) {
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
                            self.users.add(userId, { state: self.users.states.revoked });
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

    Mfa.prototype.startAuthentication = function (userId, userPin, successCb, errorCb) {
        var self = this;

        self._getPass(userId, userPin, false, function (err, data) {
            if (err) {
                return errorCb(err);
            }
            successCb(data);
        });
    };

    Mfa.prototype.finishAuthentication = function (userId, authOTT, successCb, errorCb) {
        var self = this, requestData;

        requestData = {
            "mpinResponse": {
                "authOTT": authOTT
            }
        };

        this.request({ url: this.options.settings.authenticateURL, type: "POST", data: requestData }, function (err, data) {
            if (err) {
                // Revoked identity
                if (err.status === 410) {
                    self.users.add(userId, { state: self.users.states.revoked });
                }

                return errorCb(err);
            }

            self.users.updateLastUsed(userId);

            successCb(data);
        });
    };

    Mfa.prototype._getPass = function (userId, userPin, requestOTP, callback) {
        var self = this,
            X = [],
            SEC = [];

        self._getPass1(userId, userPin, X, SEC, function (err, pass1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getPass2(userId, pass1Data.y, X, SEC, requestOTP, callback);
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
     *    UT: UT_hex, // Hex encoded X.(map_to_curve(MPIN_ID) + map_to_curve(DATE|sha256(MPIN_ID))
     *    U: U_hex, // Hex encoded X.(map_to_curve(MPIN_ID))
     *    pass: 1 // Protocol first pass
     * }
     */
    Mfa.prototype._getPass1 = function (userId, userPin, X, SEC, callback) {
        var mpinIdHex = this.users.get(userId, "mpinId"),
            tokenHex = this.users.get(userId, "token"),
            mpinIdBytes = this._hexToBytes(mpinIdHex),
            tokenBytes = this._hexToBytes(tokenHex),
            timePermitBytes = this._hexToBytes(0),
            U = [],
            UT = [],
            errorCode,
            requestData;

        errorCode = this.mpin.CLIENT_1(this.mpin.HASH_TYPE, 0, mpinIdBytes, this.rng, X, userPin, tokenBytes, SEC, U, UT, timePermitBytes);
        if (errorCode !== 0) {
            // TODO: fix this
            callback({ code: "PASS_1_ERROR", description: "pass1Request errorCode: " + errorCode}, null);
            return;
        }

        requestData = {
            mpin_id: mpinIdHex,
            UT: this._bytesToHex(UT),
            U: this._bytesToHex(U),
            pass: 1
        };

        this.request({ url: this.options.settings.mpinAuthServerURL + "/pass1", type: "POST", data: requestData }, callback);
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
     *    OTP: requestOTP, // Request OTP: 1 = required
     *    WID: accessNumber, // Number required for mobile authentication
     *    pass: 2 // Protocol second pass
     * }
     */
    Mfa.prototype._getPass2 = function (userId, yHex, X, SEC, requestOTP, callback) {
        var mpinIdHex = this.users.get(userId, "mpinId"),
            requestData,
            accessNumber,
            yBytes,
            errorCode;

        if (!requestOTP) {
            accessNumber = this.accessId;
        } else {
            accessNumber = "0";
        }

        yBytes = this._hexToBytes(yHex);

        // Compute V
        errorCode = this.mpin.CLIENT_2(X, yBytes, SEC);
        // TODO: fix this
        if (errorCode !== 0) {
            callback({ code: "PASS_2_ERROR", description: "pass2Request errorCode: " + errorCode}, null);
            return;
        }

        requestData = {
            mpin_id: mpinIdHex,
            V: this._bytesToHex(SEC),
            OTP: requestOTP,
            WID: accessNumber,
            pass: 2
        };

        this.request({ url: this.options.settings.mpinAuthServerURL + "/pass2", type: "POST", data: requestData}, callback);
    };

    Mfa.prototype.log = function(logMessage, errFlag) {
        if (this.options.client.debug) {
            if (errFlag) {
                console.error("[mfaLib] ", logMessage);
            } else {
                console.info("[mfaLib] ", logMessage);
            }
        }
        return this;
    };

    Mfa.prototype._getSettings = function(cb) {
        var self = this, settingUrl;

        settingUrl = this._getUrl({ url: "settings" });

        this.log(DebugMessages.init.url + settingUrl).request({ url: settingUrl }, function(err, settingsData) {
            if (err) {
                return cb(err, null);
            }
            self.options.settings = settingsData;
            cb(null, true);
        });
    };

    Mfa.prototype._getUrl = function(type) {
        var url;

        switch (type.url) {
            case "settings":
                url = this.options.client.server;
                url += (url.slice(-1) === "/") ? "" : "/";
                url += "rps/clientSettings";
                break;

            case "register":
                url = this.options.settings.registerURL;
                break;

            case "signature":
                url = this.options.settings.signatureURL + "/";
                url += this.users.get(type.userId, "mpinId");
                url += "?regOTT=" + Registration.regOTT;
                break;
        }

        return url;
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
        var url, type, request;

        if (typeof callback !== "function") {
            return Errors.missingCallback;
        }

        request = new XMLHttpRequest();

        url = options.url || "";
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
                    callback({ code: "REQUEST_ERROR", description: description, status: request.status }, null);
                } else {
                    callback({ code: "REQUEST_ABORTED", description: "The request was aborted", status: request.status }, null);
                }
            }
        };

        request.open(type, url, true);
        request.setRequestHeader("X-MIRACL-CID", this.options.client.customerId);
        if (options.data) {
            request.setRequestHeader("Content-Type", "application/json");
            request.send(JSON.stringify(options.data));
        } else {
            request.send();
        }

        return request;
    };

    Mfa.prototype.restore = function() {
        this.options = {};
    };

    /**
     * Calculates the MPin Token
     * This function convert mpin_id _hex to unicode. It then maps the mpin_id
     * to a point on the curve, multiplies this value by PIN and then subtracts
     * it from the client_secret curve point to generate the M-Pin token.
     *
     * @param PIN: Four digit PIN
     * @param clientSecretHex: Hex encoded client secret
     * @param mpinIdHex: Hex encoded M-Pin ID
     * @return Hex encoded M-Pin Token
     */
    Mfa.prototype._calculateMPinToken = function (mpinIdHex, PIN, clientSecretHex) {
        var self = this,
            clientSecretBytes = [],
            mpinIdBytes = [],
            errorCode;

        clientSecretBytes = self._hextobytes(clientSecretHex);
        mpinIdBytes = self._hextobytes(mpinIdHex);

        errorCode = this.mpin.EXTRACT_PIN(this.mpin.HASH_TYPE, mpinIdBytes, PIN, clientSecretBytes);
        // TODO: change this
        if (errorCode !== 0) {
            this.log("calculateMPinToken errorCode: " + errorCode);
            return errorCode;
        }

        return this.mpin.bytestostring(clientSecretBytes);
    };

    /**
     * Add two points on the curve that are originally in hex format
     * This function is used to add client secret shares.
     *
     * @param share1Hex: Hex encoded point on the curve which represents a client secret share
     * @param share2Hex: Hex encoded point on the curve which represents a client secret share
     * @return Hex encoded sum of the shares
     */
    Mfa.prototype._addShares = function (share1Hex, share2Hex) {
        var self = this,
            share1Bytes = [],
            share2Bytes = [],
            sumBytes = [],
            errorCode;

        share1Bytes = self._hextobytes(share1Hex);
        share2Bytes = self._hextobytes(share2Hex);

        errorCode = this.mpin.RECOMBINE_G1(share1Bytes, share2Bytes, sumBytes);
        // TODO: change this
        if (errorCode !== 0) {
            this.log("addShares errorCode: " + errorCode);
            return errorCode;
        }

        return this.mpin.bytestostring(sumBytes);
    };

    /**
     * Convert a hex representation of a Point to a bytes array
     *
     * @param hexValue: Hex encoded byte value
     * @return Input value in bytes
     */
    Mfa.prototype._hextobytes = function (hexValue) {
        var len, byteValue, i;

        len = hexValue.length;
        byteValue = [];

        for (i = 0; i < len; i += 2) {
            byteValue[(i / 2)] = parseInt(hexValue.substr(i, 2), 16);
        }

        return byteValue;
    };

    /**
     * USER MANAGEMENT
     */
    Users = function (customerId) {
        this.customerId = customerId;
        this.loadData();
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

    Users.prototype.add = function(userId, userData) {
        var i, uKey;

        if (!this.exists(userId)) {
            this.data.push({
                userId: userId,
                customerId: this.customerId,
                state: this.states.invalid
            });
        }

        for (i = 0; i < this.data.length; ++i) {
            if (this.data[i].userId === userId && this.data[i].customerId === this.customerId) {
                for (uKey in userData) {
                    if (userData[uKey]) {
                        this.data[i][uKey] = userData[uKey];
                    }
                }
            }
        }

        this.store();
    };

    Users.prototype.updateLastUsed = function (userId) {
        this.add(userId, { lastUsed: new Date().getTime() });
        this.store();
    };

    Users.prototype.exists = function(userId) {
        return (this.get(userId, "userId") !== false);
    };

    // Possible operations: start, confirm, finish
    Users.prototype.suitableFor = function(userId, operation) {
        var userState;

        userState = this.get(userId, "state");

        switch (operation) {
            case "start":
                return true;

            case "confirm":
                return this.exists(userId) && (userState === this.states.start || userState === this.states.active);

            case "finish":
                return this.exists(userId) && userState === this.states.active;
        }

        return false;
    };

    Users.prototype.get = function(userId, userProperty) {
        var i;

        for (i = 0; i < this.data.length; ++i) {
            if (this.data[i].userId === userId && this.data[i].customerId === this.customerId) {
                return this.data[i][userProperty] || "";
            }
        }

        return false;
    };

    Users.prototype.list = function() {
        var usersList = {}, i;

        for (i = 0; i < this.data.length; ++i) {
            if (this.data[i].customerId === this.customerId) {
                usersList[this.data[i].userId] = this.data[i].state;
            }
        }

        return usersList;
    };

    Users.prototype.delete = function(userId) {
        var i;

        if (this.exists(userId)) {
            for (i = 0; i < this.data.length; ++i) {
                if (this.data[i].userId === userId && this.data[i].customerId === this.customerId) {
                    this.data.splice(i, 1);
                }
            }
        }

        this.store();
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
