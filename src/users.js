/**
 * User management utility. Initialized by {@link Client}
 * @class
 *
 * @param {Object} storage
 * @param {string} projectId
 * @param {string} storageKey
 */
export default function Users(storage, projectId, storageKey) {
    var self = this;

    if (typeof storage.getItem !== "function" || typeof storage.setItem !== "function") {
        throw new Error("Invalid user storage object");
    }

    if (!projectId) {
        throw new Error("Project ID must be provided when configuring storage");
    }

    if (!storageKey) {
        throw new Error("Storage key must be provided when configuring storage");
    }

    self.storage = storage;
    self.projectId = projectId;
    self.storageKey = storageKey;

    self.loadData();
}

Users.prototype.data = [],

Users.prototype.states = {
    start: "STARTED",
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
            projectId: self.projectId,
            state: self.states.invalid,
            created: Math.round(new Date().getTime() / 1000)
        });
    }

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
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
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
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
        if (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId) {
            usersList[self.data[i].userId] = self.data[i].state;
        }
    }

    return usersList;
};

/**
 * Remove an identity
 * @param {string} userId - The ID of the user
 */
Users.prototype.remove = function (userId) {
    var self = this, i;

    if (!self.exists(userId)) {
        return;
    }

    for (i = 0; i < self.data.length; ++i) {
        if (self.data[i].userId === userId && (self.data[i].projectId === self.projectId || self.data[i].customerId === self.projectId)) {
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
