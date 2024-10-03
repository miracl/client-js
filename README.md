# Headless MFA Client Library

## Installation

```sh
npm install
npm run build
```

## Running Tests

Install development dependencies:

```sh
npm install
npm test
```

## Available options

```js
var options = {
	projectId: "projectId", // required
	seed: "hexEncodedRandomNumberGeneratorSeed", // required
	userStorage: localStorage, // required
	deviceName: "Name of Device"
}

var client = new MIRACLTrust(options);
```

## Build in Docker image

```sh
docker run -v $PWD:/src -w /src node:alpine npm run build
```
