var inits = function () {
	var testData = {};

	testData.userId = "test@user.de";
	
	testData.init = {};
	testData.init.server = "http://server.com";
	testData.init.distributor = "mlg";

	testData.settings = {
		certivoxURL: "https://miracl.com",
		dtaUrl: "https://api.miracl.net",
		registerURL: "https://api.miracl.net/register/user",
		signatureURL: "https://api.miracl.net/signature"
	};

	testData.users = {
		data: {
			"test@user.de": {
				mpinId: "exampleMpinId",
				csHex: "testCsHex"
			}
		}
	}

	testData.cs1 = {
		clientSecret: "clientSecretValue"
	};

	testData.cs2 = {
		clientSecretShare: "clientSecretValue"
	};

	return {
		testData: testData
	}
}();

if (typeof module !== "undefined" && typeof module.exports !== "undefined")
  module.exports = inits;
else
  window.inits = inits;
