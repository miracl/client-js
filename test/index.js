if (typeof require !== 'undefined') {
    var expect = require('chai').expect;
    var sinon = require('sinon');
    var Mfa = require('../index');
}

var testData = {};

testData.server = "http://server.com";

describe("Mfa Client", function() {
    it("should throw Error w/o init server", function() {
        var mfa = new Mfa();
        expect(mfa).to.be.an.instanceof(Error);
    });

    it("should be OK", function() {
        var mfa = new Mfa({
            server: testData.server
        });

        expect(mfa).to.be.ok;
    });
});
