export function parseUriParams (uri) {
    const query = uri.split("?").pop();
    const queryArr = query.split("&");

    const params = {};

    if (!query.length || !queryArr.length) {
        return params;
    }

    for (let i = 0; i < queryArr.length; i++) {
        const pairArr = queryArr[i].split("=");
        params[pairArr[0]] = decodeURIComponent(pairArr[1].replace(/\+/g, " "));
    }

    return params;
}
