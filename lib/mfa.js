var Mfa = Mfa || {};

(function() {
    "use strict";

    var Errors = {},
        usersData = [],
        DebugMessages = {},
        Users;

    Errors.missingServer = { code: "MISSING_SERVER", description: "Missing server parameter" };
    Errors.missingCustomerId = { code: "MISSING_CUSTOMER_ID", description: "Missing customer ID" };
    Errors.missingCallback = { code: "MISSING_CALLBACK", description: "Bad or missing callback" };
    Errors.identityNotVerified = { code: "IDENTITY_NOT_VERIFIED", description: "Identity not Verified" };
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

        this.options = {};
        this.options.client = options;
        this.log(DebugMessages.construct);

        this.users = new Users(options.customerId);
    };

    Mfa.prototype.options = {};

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

        token = MPINAuth.calculateMPinToken(this.users.get(userId, "mpinId"), userPin, this.users.get(userId, "csHex"));
        userData = {
            token: token,
            state: this.users.states.register
        };
        this.users.add(userId, userData);
        this.users.store();

        successCb(userData);
    };

    Mfa.prototype.toHash = function(strData) {
        var hash = 0;
        for (var i = 0; i < strData.length; i++) {
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
            var userData;
            if (err) {
                return cb(err, null);
            }

            userData = typeof data === "string" ? JSON.parse(data) : data;
            userData.state = (data.active) ? self.users.states.active : self.users.states.start;
            self.users.add(userId, userData);
            cb(null, userData);
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
            var userData, csHex;

            if (err) {
                return cb(err, null);
            }
            csHex = MPINAuth.addShares(sec1Data.clientSecretShare, sec2Data.clientSecret);

            userData = {
                csHex: csHex,
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
            successCb(data);
        });
    };

    Mfa.prototype._getPass = function (userId, userPin, requestOTP, callback) {
        var self = this;

        self._getPass1(userId, userPin, function (err, pass1Data) {
            if (err) {
                return callback(err, null);
            }

            self._getPass2(userId, pass1Data.y, requestOTP, callback);
        });
    };

    Mfa.prototype._getPass1 = function (userId, userPin, callback) {
        var mpinIdHex = this.users.get(userId, "mpinId"),
            tokenHex = this.users.get(userId, "token"),
            requestData;

        requestData = MPINAuth.pass1Request(mpinIdHex, tokenHex, 0, userPin, 0, null);

        this.request({ url: this.options.settings.mpinAuthServerURL + "/pass1", type: "POST", data: requestData }, callback);
    };

    Mfa.prototype._getPass2 = function (userId, yHex, requestOTP, callback) {
        var requestData, wid;

        if (!requestOTP) {
            wid = this.accessId;
        } else {
            wid = "0";
        }

        requestData = MPINAuth.pass2Request(yHex, requestOTP, wid);
        requestData.mpin_id = this.users.get(userId, "mpinId");

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
                url += "?regOTT=" + this.users.get(type.userId, "regOTT");
                break;
        }

        return url;
    };

    Mfa.prototype.request = function (options, callback) {
        var url, type, request;

        if (typeof callback !== "function") {
            return Errors.missingCallback;
        }

        request = new XMLHttpRequest();

        url = options.url || "";
        type = options.type || "GET";

        request.onreadystatechange = function () {
            if (request.readyState === 4 && request.status === 200) {
                var response;
                try {
                    response = JSON.parse(request.responseText);
                } catch (e) {
                    response = request.responseText;
                }
                callback(null, response);
            } else if (request.readyState === 4) {
                var description;
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
     * USER MANAGEMENT
     */
    Users = function (customerId) {
        usersData = JSON.parse(localStorage.getItem(this.storageKey)) || [];
        this.customerId = customerId;
    };

    Users.prototype.storageKey = "mfa";

    Users.prototype.states = {
        invalid: "INVALID",
        start: "STARTED",
        active: "ACTIVATED",
        register: "REGISTERED",
        revoked: "REVOKED"
    };

    Users.prototype.add = function(userId, userData) {
        var i, uKey;

        if (!this.exists(userId)) {
            usersData.push({
                userId: userId,
                customerId: this.customerId,
                state: this.states.invalid
            });
        }

        for (i = 0; i < usersData.length; ++i) {
            if (usersData[i].userId == userId && usersData[i].customerId === this.customerId) {
                for (uKey in userData) {
                    if (userData[uKey]) {
                        usersData[i][uKey] = userData[uKey];
                    }
                }
            }
        }
    };

    Users.prototype.exists = function(userId) {
        return (this.get(userId, "userId") !== false);
    };

    // operation: start, confirm, finish
    Users.prototype.suitableFor = function(userId, operation) {
        var suitableFlag, userState;

        userState = this.get(userId, "state");

        switch (operation) {
            case "start":
                suitableFlag = true;
                break;

            case "confirm":
                if (!this.exists(userId)) {
                    suitableFlag = false;
                } else if (userState === this.states.start) {
                    suitableFlag = true;
                } else if (userState === this.states.active) {
                    suitableFlag = true;
                } else {
                    suitableFlag = false;
                }
                break;

            case "finish":
                if (!this.exists(userId)) {
                    suitableFlag = false;
                } else if (userState === this.states.active) {
                    suitableFlag = true;
                } else {
                    suitableFlag = false;
                }
                break;

            default:
                suitableFlag = false;
        }

        return suitableFlag;
    };

    Users.prototype.get = function(userId, userProperty) {
        var i;

        for (i = 0; i < usersData.length; ++i) {
            if (usersData[i].userId === userId && usersData[i].customerId === this.customerId) {
                return usersData[i][userProperty] || "";
            }
        }

        return false;
    };

    Users.prototype.list = function() {
        var usersList = {}, i;

        for (i = 0; i < usersData.length; ++i) {
            if (usersData[i].customerId == this.customerId) {
                usersList[usersData[i].userId] = usersData[i].state;
            }
        }

        return usersList;
    };

    Users.prototype.delete = function(userId) {
        var i;

        if (this.exists(userId)) {
            for (i = 0; i < usersData.length; ++i) {
                if (usersData[i].userId === userId && usersData[i].customerId === this.customerId) {
                    usersData.splice(i, 1);
                }
            }
        }

        this.store();
    };

    Users.prototype.store = function() {
        localStorage.setItem(this.storageKey, JSON.stringify(usersData));
    };

})();

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = Mfa;
}
