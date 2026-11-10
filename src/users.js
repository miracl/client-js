/**
 * User management utility. Initialized by {@link Client}
 */
export default class Users {
    /**
     * @param {Object} storage
     * @param {string} projectId
     * @param {string} storageKey
     */
    constructor(storage, projectId, storageKey) {
        if (typeof storage.getItem !== "function" || typeof storage.setItem !== "function") {
            throw new Error("Invalid user storage object");
        }

        if (!projectId) {
            throw new Error("Project ID must be provided when configuring storage");
        }

        if (!storageKey) {
            throw new Error("Storage key must be provided when configuring storage");
        }

        this.storage = storage;
        this.projectId = projectId;
        this.storageKey = storageKey;

        this.data = [];
        this.loadData();

        this.states = {
            start: "STARTED",
            register: "REGISTERED",
            revoked: "REVOKED"
        };
    }

    loadData() {
        this.data = JSON.parse(this.storage.getItem(this.storageKey)) || [];

        this.store();

        // Sort list by last used timestamp
        this.data.sort((a, b) => {
            if (a.lastUsed && (!b.lastUsed || a.lastUsed > b.lastUsed)) {
                return 1;
            }

            if (b.lastUsed && (!a.lastUsed || a.lastUsed < b.lastUsed)) {
                return -1;
            }

            return 0;
        });
    }

    write(userId, userData) {
        if (!this.exists(userId)) {
            this.data.push({
                userId: userId,
                projectId: this.projectId,
                state: this.states.invalid,
                created: Math.round(new Date().getTime() / 1000)
            });
        }

        for (let i = 0; i < this.data.length; ++i) {
            if (this.data[i].userId === userId && (this.data[i].projectId === this.projectId || this.data[i].customerId === this.projectId)) {
                for (const uKey in userData) {
                    if (userData[uKey]) {
                        this.data[i][uKey] = userData[uKey];
                    }
                }
            }
        }

        this.store();
    }

    updateLastUsed(userId) {
        this.write(userId, { lastUsed: new Date().getTime() });
    }

    /**
     * Check if an user with the specified User ID exists
     * @param {string} userId - The ID of the user
     * @returns {boolean}
     */
    exists(userId) {
        return typeof this.get(userId, "userId") !== "undefined";
    }

    /**
     * Check if an user is in a specific state
     * @param {string} userId - The ID of the user
     * @param {string} state - The state to check for
     * @returns {boolean} - Returns true if the state of the user matches the state argument
     */
    is(userId, state) {
        return this.get(userId, "state") === state;
    }

    /**
     * Get a property of the user
     * @param {string} userId - The ID of the user
     * @param {string} userProperty - The name of the property to be fetched
     * @returns {string} - The value of the user property. Will return undefined if property doesn't exist
     */
    get(userId, userProperty) {
        for (let i = 0; i < this.data.length; ++i) {
            if (this.data[i].userId === userId && (this.data[i].projectId === this.projectId || this.data[i].customerId === this.projectId)) {
                if (userProperty) {
                    // Return requested property
                    return this.data[i][userProperty] || "";
                } else {
                    // Return the whole user data if no property is requested
                    return this.data[i];
                }
            }
        }
    }

    /**
     * List all identities
     * @returns {Object}
     */
    list() {
        const usersList = {};
        for (let i = 0; i < this.data.length; ++i) {
            if (this.data[i].projectId === this.projectId || this.data[i].customerId === this.projectId) {
                usersList[this.data[i].userId] = this.data[i].state;
            }
        }

        return usersList;
    }

    /**
     * Returns an array of all user objects
     * @returns {Array}
     */
    all() {
        const users = [];
        for (let i = 0; i < this.data.length; ++i) {
            if (this.data[i].projectId === this.projectId || this.data[i].customerId === this.projectId) {
                users.push(this.data[i]);
            }
        }

        return users;
    }

    /**
     * Returns the number of registered identities
     * @return {number}
     */
    count() {
        return Object.keys(this.list()).length;
    }

    /**
     * Remove an identity
     * @param {string} userId - The ID of the user
     */
    remove(userId) {
        if (!this.exists(userId)) {
            return;
        }

        for (let i = 0; i < this.data.length; ++i) {
            if (this.data[i].userId === userId && (this.data[i].projectId === this.projectId || this.data[i].customerId === this.projectId)) {
                this.data.splice(i, 1);
            }
        }

        this.store();
    }

    store() {
        // Ensure that there is no sensitive data before storing it
        for (let i = 0; i < this.data.length; ++i) {
            delete this.data[i].csHex;
            delete this.data[i].regOTT;
        }

        this.storage.setItem(this.storageKey, JSON.stringify(this.data));
    }
}
