import Client from "./client.js";

export default class PromiseInterface extends Client {
    fetchAccessId(userId) {
        return promisify(super.fetchAccessId.bind(this), userId);
    }

    fetchStatus() {
        return promisify(super.fetchStatus.bind(this));
    }

    sendPushNotificationForAuth(userId) {
        return promisify(super.sendPushNotificationForAuth.bind(this), userId);
    }

    sendVerificationEmail(userId) {
        return promisify(super.sendVerificationEmail.bind(this), userId);
    }

    getActivationToken(verificationURI) {
        return promisify(super.getActivationToken.bind(this), verificationURI);
    }

    register(userId, activationToken, pinCallback) {
        return promisify(super.register.bind(this), userId, activationToken, pinCallback);
    }

    authenticate(userId, userPin) {
        return promisify(super.authenticate.bind(this), userId, userPin);
    }

    authenticateWithQRCode(userId, qrCode, userPin) {
        return promisify(super.authenticateWithQRCode.bind(this), userId, qrCode, userPin);
    }

    authenticateWithAppLink(userId, appLink, userPin) {
        return promisify(super.authenticateWithAppLink.bind(this), userId, appLink, userPin);
    }

    authenticateWithNotificationPayload(payload, userPin) {
        return promisify(super.authenticateWithNotificationPayload.bind(this), payload, userPin);
    }

    generateQuickCode(userId, userPin) {
        return promisify(super.generateQuickCode.bind(this), userId, userPin);
    }

    sign(userId, userPin, message, timestamp) {
        return promisify(super.sign.bind(this), userId, userPin, message, timestamp);
    }
}

function promisify (original, ...args) {
    return new Promise((resolve, reject) => {
        original(...args, function (err, result) {
            if (err) {
                reject(err);
                return;
            }

            resolve(result);
        });
    });
}
