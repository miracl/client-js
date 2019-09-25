# Headless MFA Client Library

[![pipeline status](https://gitlab.corp.miracl.com/mfa/maas/pkg/client-js/badges/master/pipeline.svg)](https://gitlab.corp.miracl.com/mfa/maas/pkg/client-js/commits/master)
[![coverage report](https://gitlab.corp.miracl.com/mfa/maas/pkg/client-js/badges/master/coverage.svg)](https://gitlab.corp.miracl.com/mfa/maas/pkg/client-js/commits/master)

## Installation

```bash
$ git clone
$ cd project_folder
$ npm install
$ npm run build
```

## Running Tests

Install development dependencies:

```bash
$ npm install
```

Then:

```bash
$ npm test
```

## Available options

```
var mfaOptions = {
	server: "serverUrl", // required
	customerId: "customerId", // required
	seed: "hexEncodedRandomNumberGeneratorSeed", // required
	deviceName: "Name of Device"
}
var mfa = new Mfa(mfaOptions);
```

## Build in Docker image

```
docker run -v $PWD:/src -w /src node:alpine npm run build
```
