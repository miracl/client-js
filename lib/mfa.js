var Mfa = Mfa || {};

(function() {
    var Errors = {};
    Errors.missingServer = "Mising server parameter";

    Mfa = function(options) {
        if (!options || !options.server) {
            return new Error(Errors.missingServer);
        }
    };

})();

if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = Mfa;
}
