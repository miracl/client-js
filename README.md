# MIRACL Trust Client JS Library

## Installation

MIRACL Trust Client JS Library is available as an NPM package.

```sh
npm install --save @miracl/client-js
```

You can include the library in your build toolchain either as an ECMAScript or a
CommonJS module. The library provides both a Node-style callback interface and a
promise interface.

ESM:

```js
// Callback interface
import MIRACLTrust from "@miracl/client-js";
// Promise interface
import MIRACLTrust from "@miracl/client-js/promise";
```

CJS:

```js
// Callback interface
const MIRACLTrust = require("@miracl/client-js");
// Promise interface
const MIRACLTrust = require("@miracl/client-js/promise");
```

You can also use the pre-built browser version located in the `dist/` directory:

```html
<!-- Callback interface -->
<script src="dist/client.min.js"></script>
<!-- Promise interface -->
<script src="dist/client.promise.min.js"></script>
```

## Usage

### Configuration

To configure the library:

1. Create an application in the MIRACL Trust platform. For information about how
   to do it, see the
   [Getting Started](https://miracl.com/resources/docs/guides/get-started/)
   guide.
2. Create a new instance of MIRACLTrust and pass the configuration as an object:

```js
const mcl = new MIRACLTrust({
  projectId: "<YOUR_PROJECT_ID>", // required
  seed: "hexEncodedRandomNumberGeneratorSeed", // required
  userStorage: localStorage, // required
  deviceName: "Name of Device",
  cors: true,
});
```

The seed is used for initializing the random number generator necessary for the
security of the authentication protocol. Here is an example implementation
compatible with most browsers:

```js
function getLocalEntropy() {
  const crypto = window.crypto || window.msCrypto;

  if (typeof crypto === "undefined") {
    throw new Error("Crypto API unavailable");
  }

  const buffer = new Uint32Array(8);
  crypto.getRandomValues(buffer);

  let entropyHex = "";
  for (let i = 0; i < buffer.length; i++) {
    entropyHex = entropyHex + buffer[i].toString(16);
  }

  return entropyHex;
}
```

### User ID Verification

To register a new User ID, you need to verify it. MIRACL Trust offers two
options for that:

- [Custom User Verification](https://miracl.com/resources/docs/guides/custom-user-verification/)
- Built-in Email Verification

  With this type of verification, the end user's email address serves as the
  User ID. Currently, MIRACL Trust provides two kinds of built-in email
  verification methods:

  - [Email Link](https://miracl.com/resources/docs/guides/built-in-user-verification/email-link/)
    (default)
  - [Email Code](https://miracl.com/resources/docs/guides/built-in-user-verification/email-code/)

  Start the verification by calling the `sendVerificationEmail` method:

  Promise:

  ```js
  try {
    const result = await mcl.sendVerificationEmail(userId);
    console.log(result);
  } catch (err) {
    // Handle any potential errors
  }
  ```

  Callback:

  ```js
  mcl.sendVerificationEmail(userId, function (err, result) {
    if (err) {
      // Handle any potential errors
    }

    console.log(result);
  });
  ```

  Then, a verification email is sent, and a response with backoff and email
  verification method is returned.

  If the verification method you have chosen for your project is:

  - **Email Code:**

    You must check the email verification method in the response.

    - If the end user is registering for the first time or resetting their PIN,
      an email with a verification code will be sent, and the email verification
      method in the response will be `code`. Then, ask the end user to enter the
      code in the application.

    - If the end user has already registered another device with the same User
      ID, a Verification URL will be sent, and the verification method in the
      response will be `link`. In this case, proceed as described for the
      **Email Link** verification method below.

  - **Email Link:** Your application must open when the end user follows the
    Verification URL in the email.

### Registration

1. To register the mobile device, get an activation token using the
   `getActivationToken` method and the received Verification URL:

Promise:

```js
try {
  const result = await mcl.getActivationToken(
    "https://yourdomain.com/verification/confirmation?userId=alice@miracl.com&code=theVerificationCode",
  );
  console.log(result.actToken);
} catch (err) {
  switch (error.message) {
    case "Unsuccessful verification":
      break;
    default:
    // Handle any unexpected errors
  }
}
```

Callback:

```js
mcl.getActivationToken(
  "https://yourdomain.com/verification/confirmation?userId=alice@miracl.com&code=theVerificationCode",
  function callback(err, result) {
    if (err) {
      switch (error.message) {
        case "Unsuccessful verification":
          break;
        default:
        // Handle any unexpected errors
      }
    }

    console.log(result.actToken);
  },
);
```

An "Unsuccessful verification" error can be returned if the code is invalid or
expired.

2. Pass the User ID (email or any string you use for identification) and
   activation token to the `register` method.

Promise:

```js
try {
  const result = await mcl.register(userId, actToken, function (passPin) {
    // Here you need to prompt the user for their PIN
    // and then call the passPin argument with the value
    passPin(pin);
  });
  console.log(result);
} catch (err) {
  // Handle any potential errors
}
```

Callback:

```js
mcl.register(
  userId,
  actToken,
  function (passPin) {
    // Here you need to prompt the user for their PIN
    // and then call the passPin argument with the value
    passPin(pin);
  },
  function callback(err) {
    if (err) {
      // Handle any potential errors
    }
  },
);
```

If you call the `register` method with the same User ID more than once, the User
ID will be overridden. Therefore, you can use it when you want to reset your
authentication PIN code.

### Authentication

MIRACL Trust Client JS Library offers two options:

- [Authenticate users on the same application](#authenticate-users-on-the-same-application)
- [Authenticate users on another application](#authenticate-users-on-another-application)

#### Authenticate users on the same application

The `authenticate` method generates a
[JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication token for а
registered user.

Promise:

```js
try {
  const result = await mcl.authenticate(userId, pin);
  console.log(result.jwt);
} catch (err) {
  switch (error.message) {
    case "Unsuccessful authentication":
      break;
    case "Revoked":
      break;
    default:
    // Handle any unexpected errors
  }
}
```

Callback:

```js
mcl.authenticate(userId, pin, function callback(err, result) {
  if (err) {
    switch (error.message) {
      case "Unsuccessful authentication":
        break;
      case "Revoked":
        break;
      default:
      // Handle any unexpected errors
    }
  }

  // The JWT in the result needs to be verified by your back end
  // to ensure that the authentication was successful
  console.log(result.jwt);
});
```

"Unsuccessful authentication" is returned when there is a discrepancy in the
cryptographic calculations between the client and the server. This may be due to
an incorrect PIN input or an issue with the token.

"Revoked" is returned after the third consecutive failed authentication attempt,
and for any subsequent attempts after the revocation. This error may also occur
if the device registration has been explicitly revoked by an administrator via
the MIRACL Trust Console or through the revocation API.

After the JWT authentication token is generated, it needs to be sent to the
application server for verification. Then, the application server verifies the
token signature using the MIRACL Trust
[JWKS](https://api.mpin.io/.well-known/jwks) endpoint and the `audience` claim,
which in this case is the application Project ID.

#### Authenticate users on another application

When using the library to build a hybrid mobile application, you can use it as
an authenticator to authenticate a user on another application or device. There
are three options:

- Authenticate with [AppLink](https://developer.android.com/training/app-links)

  Use the `authenticateWithAppLink` method:

  ```js
  try {
    await mcl.authenticateWithAppLink(userId, appLink, pin);
  } catch (err) {
    // Handle any potential errors
  }
  ```

- Authenticate with QR code

  Use the `authenticateWithQRCode` method:

  ```js
  try {
    await mcl.authenticateWithQRCode(userId, qrCode, pin);
  } catch (err) {
    // Handle any potential errors
  }
  ```

- Authenticate with a push notification

  Use the `authenticateWithNotificationPayload` method:

  ```js
  try {
    await mcl.authenticateWithNotificationPayload(pushNotificationPayload, pin);
  } catch (err) {
    // Handle any potential errors
  }
  ```

For more information about authenticating users on separate applications and
devices, see
[Cross-Device Authentication](https://miracl.com/resources/docs/guides/how-to/custom-mobile-authentication/).

### Signing

DVS stands for Designated Verifier Signature, which is a protocol for
cryptographic signing of documents. For more information, see
[Designated Verifier Signature](https://miracl.com/resources/docs/concepts/dvs/).
In the context of this library, we refer to it as ‘Signing’.

To sign a document, use the `sign` method as follows:

Promise:

```js
try {
  const signature = await mcl.sign(
    userId,
    pin,
    documentHash,
    documentTimestamp,
  );
  console.log(signature);
} catch (err) {
  // Handle any potential errors
}
```

Callback:

```js
mcl.sign(
  userId,
  pin,
  documentHash,
  documentTimestamp,
  function callback(err, signature) {
    if (err) {
      // Handle any potential errors
      return;
    }

    console.log(signature);
  },
);
```

The signature needs to be verified. This is done when the signature is sent to
the application server, which then makes an HTTP call to the
[POST /dvs/verify](https://miracl.com/resources/docs/apis-and-libraries/backend-api/verify-dvs-signature/)
endpoint. If the MIRACL Trust platform returns status code `200`, the
`certificate` entry in the response body indicates that signing is successful.

### QuickCode

[QuickCode](https://miracl.com/resources/docs/guides/built-in-user-verification/quickcode/)
is a way to register another device without going through the verification
process.

To generate a QuickCode, call the `generateQuickCode` method:

Promise:

```js
try {
  const result = await mcl.generateQuickCode(userId, pin);
  console.log(result.code);
} catch (err) {
  // Handle any potential errors
}
```

Callback:

```js
mcl.generateQuickCode(userId, pin, function callback(err, result) {
  if (err) {
    // Handle any potential errors
  }

  console.log(result.code);
});
```

### User Management

When instantiated, the library automatically initialises a user management
object, which can be accessed via the MIRACLTrust.users property and includes
the following methods:

#### List

To retrieve all registered User IDs on the current device, use the `list`
method:

```js
const list = mcl.users.list();
```

#### Еxists

To check if a User ID is already registered on the device, use the `exists`
method:

```js
const exists = mcl.users.exists("alice@miracl.com");
```

#### Remove

To delete the registration on the current device for a specified User ID, use
the `remove` method:

```js
mcl.users.remove("alice@miracl.com");
```

> Note that this only affects the device on which it's executed. Any other
> registered devices will still be able to authenticate.
