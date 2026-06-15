export default function HTTP(timeout, clientName, projectId, cors) {
    this.requestTimeout = timeout;
    this.clientName = clientName;
    this.projectId = projectId;
    this.cors = cors;
}

/**
 * Make an HTTP request
 * @private
 */
HTTP.prototype.request = function (options, callback) {
    if (typeof callback !== "function") {
        throw new Error("Bad or missing callback");
    }

    if (!options.url) {
        throw new Error("Missing URL for request");
    }

    const request = new XMLHttpRequest();

    request.onreadystatechange = function () {
        let response;

        if (request.readyState === 4 && request.status === 200) {
            try {
                response = JSON.parse(request.responseText);
            } catch (e) {
                response = request.responseText;
            }

            callback(null, response);
        } else if (request.readyState === 4) {
            if (request.status === 0) {
                callback(new Error("The request was aborted"), { status: 0 });
                return;
            }

            try {
                response = JSON.parse(request.responseText);
            } catch (e) {
                callback(new Error(request.statusText), { status: request.status });
                return;
            }

            callback(new Error(response.info), {
                status: request.status,
                error: response.error,
                context: response.context
            });
        }
    };

    let url = options.url;
    if (this.cors) {
        url += (url.indexOf("?") !== -1 ? "&" : "?") + "project_id=" + this.projectId;
    }

    const type = options.type || "GET";

    request.open(type, url, true);

    request.timeout = this.requestTimeout;

    request.setRequestHeader("X-MIRACL-CID", this.projectId);
    request.setRequestHeader("X-MIRACL-CLIENT", this.clientName);

    // Set authorization header if provided
    if (options.authorization) {
        request.setRequestHeader("Authorization", options.authorization);
    }

    if (options.data) {
        request.setRequestHeader("Content-Type", "application/json");
        request.send(JSON.stringify(options.data));
    } else {
        request.send();
    }

    return request;
};
