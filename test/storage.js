// Mock in-memory user storage
var UserStorage = function () {
    this.storage = {};
};

UserStorage.prototype.setItem = function (key, value) {
    this.storage[key] = value || '';
};

UserStorage.prototype.getItem = function (key) {
    return this.storage[key] ? this.storage[key] : null;
};

UserStorage.prototype.removeItem = function (key) {
    delete this.storage[key];
};

UserStorage.prototype.clear = function (key) {
    this.storage = {};
};

module.exports = UserStorage;
