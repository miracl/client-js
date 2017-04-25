var Mfa = Mfa || {};

(function() {
    "use strict";
    var Errors = {},
        Users = { data: {} },
        States = {},
        DebugMessages = {};

    Errors.missingServer = { code: "MISSING_SERVER", description: "Missing server parameter" };
    Errors.missingDistributor = { code: "MISSING_DISTRIBUTOR", description: "Missing Distributor" };
    Errors.missingCallback = { code: "MISSING_CALLBACK", description: "Bad or missing callback" };
    Errors.identityNotVerified = { code: "IDENTITY_NOT_VERIFIED", description: "Identity not Verified" };
    Errors.missingUserId = { code: "MISSING_USERID", description: "Missing user id" };

    States.invalid = "INVALID";
    States.start = "STARTED";
    States.active = "ACTIVATED";
    States.register = "REGISTERED";
    States.block = "BLOCKED";

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
            return new Error(Errors.missingServer);
        } else if (!options.distributor) {
            return new Error(Errors.missingDistributor);
        }

        this.options = {};
        this.options.client = options;
        this.log(DebugMessages.construct);
    };

    Mfa.prototype.options = {};
    Mfa.prototype.storageKey = "mfa";


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

    Mfa.prototype.startRegistration = function(userId, successCb, errorCb) {
        var self = this;
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

    Mfa.prototype.restartRegistration = function(userId, successCb, errorCb) {
        var self = this;
        this.log(DebugMessages.start.start)._registration(userId, function(err) {
            if (err) {
                self.log(DebugMessages.start.error, true);
                return errorCb(err);
            }
            self.log(DebugMessages.start.ok);
            successCb(true);
        });
    };

    Mfa.prototype.finishRegistration = function(userId, userPin) {
        if (!userId) {
            return Errors.missingUserId;
        }
        if (isNaN(userPin)) {
            userPin = this.toHash(userPin);
        }

        var token = MPINAuth.calculateMPinToken(Users.data[userId].mpinId, userPin, Users.data[userId].csHex);

        this.addUser(userId, { token: token });
    };

    Mfa.prototype.toHash = function(strData) {
        var hash = 0;
        for (var i = 0; i < strData.length; i++) {
            hash = ((hash << 5) - hash) + strData.charCodeAt(i);
        }
        return hash;
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
        var _cs1Url;

        _cs1Url = this._getUrl({ url: "signature", userId: userId });
        this.request({ url: _cs1Url }, function(err, data) {
            if (err) {
                return cb(err, null);
            }

            cb(null, data);
        });
    };

    Mfa.prototype._getSecret2 = function(userId, sec1Data, cb) {
        var self = this,
            _cs2Url;

        _cs2Url = this.options.settings.certivoxURL;
        _cs2Url += "clientSecret?";
        _cs2Url += sec1Data.params;

        this.request({ _url: _cs2Url }, function(err, sec2Data) {
            if (err) {
                return cb(err, null);
            }
            var csHex = MPINAuth.addShares(sec1Data.clientSecret, sec2Data.clientSecretShare);

            self.addUser(userId, { csHex: csHex });
            cb(null, true);
        });
    };

    Mfa.prototype._registration = function(userId, cb) {
        var _regData = {},
            self = this;

        _regData.url = this._getUrl({ url: "register" });
        _regData.type = "PUT";
        _regData.data = {
            userId: userId,
            mobile: 0
        };
        this.request(_regData, function(err, data) {
            if (err) {
                return cb(err, null);
            }
            self.addUser(userId, data);
            cb(null, data);
        });
    };


    Mfa.prototype.addUser = function(userId, userData) {
        if (!this.checkUserExists(userId)) {
            Users.data[userId] = {};
        }

        for (var uKey in userData) {
            if (userData[uKey]) {
                Users.data[userId][uKey] = userData[uKey];
            }
        }
    };

    Mfa.prototype.checkUserExists = function(userId) {
        return Boolean(Users.data[userId]);
    };

    // remove this
    Mfa.prototype.users = function() {
        return Users;
    };

    Mfa.prototype.log = function(logMessage, errFlag) {
        if (this.options.client.debug) {
            if (errFlag) {
                console.error(".:mfaLib: ", logMessage);
            } else {
                console.info(".:mfaLib: ", logMessage);
            }
        }
        return this;
    };


    Mfa.prototype._getSettings = function(cb) {
        var _settingUrl, self = this;
        _settingUrl = this._getUrl({ url: "settings" });

        this.log(DebugMessages.init.url + _settingUrl).request({ url: _settingUrl }, function(err, settingsData) {
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
                url += "clientSettings";
                break;
            case "register":
                url = this.options.settings.registerURL;
                break;
            case "signature":
                url = this.options.settings.signatureURL + "/";
                url += Users.data[type.userId].mpinId;
                url += "?regOTT=" + Users.data[type.userId].regOTT;
                break;
        }

        return url;
    };

    Mfa.prototype.storage = function(mfaData) {
        localStorage.setItem(this.storageKey, JSON.stringify(mfaData));
    };

    Mfa.prototype.request = function(options, cb) {
        var _request = new XMLHttpRequest(),
            _url, _type;
        _url = options.url || "";
        _type = options.type || "GET";

        if (typeof cb !== "function") {
            throw new Error(Errors.missingCallback);
        }

        _request.onreadystatechange = function() {
            if (_request.readyState === 4 && _request.status === 200) {
                if (_request.responseText) {
                    try {
                        cb(null, JSON.parse(_request.responseText));
                    } catch (err) {
                        cb(null, _request.responseText);
                    }
                } else {
                    cb(null, _request);
                }
            } else if (_request.readyState === 4) {
                cb({ status: _request.status }, null);
            }
        };

        _request.open(_type, _url, true);
        _request.setRequestHeader("X-MIRACL-CID", this.options.client.distributor);
        if (options.data) {
            _request.setRequestHeader("Content-Type", "application/json");
            _request.send(JSON.stringify(options.data));
        } else {

            _request.send();
        }
    };

    Mfa.prototype.restore = function() {
        this.options = {};
    };

})();

if (typeof module !== "undefined" && typeof module.exports !== "undefined") {
    module.exports = Mfa;
}
