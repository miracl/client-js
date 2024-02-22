import HTTP from "../src/http.js";
import sinon from "sinon";
import chai from "chai";
const expect = chai.expect;

describe("HTTP request", function() {
    var client, server, requests;

    before(function () {
        var xhr = global.XMLHttpRequest = sinon.useFakeXMLHttpRequest();
        xhr.onCreate = function (xhr) {
            requests.push(xhr);
        };
    });

    beforeEach(function () {
        requests = [];
        client = new HTTP(4000, "clientName", "projectID", false);
    });

    it("should throw error missing callback", function () {
        expect(function () {
            client.request({ url: "reqUrl" });
        }).to.throw("Bad or missing callback");

        expect(function () {
            client.request({ url: "reqUrl" }, "string");
        }).to.throw("Bad or missing callback");
    });

    it("should throw error missing URL", function () {
        expect(function () {
            client.request({}, function () {});
        }).to.throw("Missing URL for request");
    });

    it("should handle successful JSON response", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-json-get"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "{ \"test\": 1 }");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, null, { test: 1 });
    });

    it("should handle JSON error response", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-json-get"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(400, { "Content-Type": "application/json" }, "{ \"error\": \"ERROR_CODE\", \"info\": \"The request was not successful\", \"context\": {\"requestID\": \"REQUEST_ID\"} }");

        expect(callback.callCount).to.equal(1);
        expect(callback.firstCall.args[0].name).to.equal("Error");
        expect(callback.firstCall.args[0].message).to.equal("The request was not successful");
        expect(callback.firstCall.args[1].status).to.equal(400);
        expect(callback.firstCall.args[1].error).to.equal("ERROR_CODE");
        expect(callback.firstCall.args[1].context).to.deep.equal({requestID: "REQUEST_ID"});
    });

    it("should handle successful text response", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-json-get"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "test");

        expect(callback.callCount).to.equal(1);
        sinon.assert.calledWith(callback, null, "test");
    });

    it("should make a post request", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-json-get",
            type: "POST",
            data: { test: 1}
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(200, { "Content-Type": "application/json" }, "{ \"test\": 1 }");

        expect(callback.callCount).to.equal(1);
    });

    it("should set Authorization Header", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-auth",
            authorization: "Bearer test"
        }, callback);

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("Authorization");
        expect(requests[0].requestHeaders["Authorization"]).to.equal("Bearer test");
        requests[0].respond(200, { "Content-Type": "application/json" }, "{ \"test\": 1 }");

        expect(callback.callCount).to.equal(1);
    });

    it("should handle error response", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-error"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(400, { }, "");

        expect(callback.callCount).to.equal(1);
        expect(callback.firstCall.args[0].name).to.equal("Error");
        expect(callback.firstCall.args[1].status).to.equal(400);
    });

    it("should handle aborted request", function () {
        var callback = sinon.spy();
        client.request({
            url: "/test-abort"
        }, callback);

        expect(requests.length).to.equal(1);
        requests[0].respond(0, { }, "");

        expect(callback.callCount).to.equal(1);
        expect(callback.callCount).to.equal(1);
        expect(callback.firstCall.args[0].name).to.equal("Error");
        expect(callback.firstCall.args[0].message).to.equal("The request was aborted");
        expect(callback.firstCall.args[1].status).to.equal(0);
    });

    it("should set project ID header", function () {
        client.request({
            url: "/test-project-id-header",
        }, function () {});

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("X-MIRACL-CID");
        expect(requests[0].requestHeaders["X-MIRACL-CID"]).to.equal("projectID");
    });

    it("should add project ID parameter for CORS requests", function () {
        client = new HTTP(4000, "clientName", "projectID", true);

        client.request({
            url: "/test-project-id-parameter",
        }, function () {});

        expect(requests.length).to.equal(1);
        expect(requests[0].url).to.contain("?project_id=projectID");
    });

    it("should set client version header", function () {
        client.request({
            url: "/test-client-version-header",
        }, function () {});

        expect(requests.length).to.equal(1);
        expect(requests[0].requestHeaders).to.have.property("X-MIRACL-CLIENT");
        expect(requests[0].requestHeaders["X-MIRACL-CLIENT"]).to.equal("clientName");
    });
});
