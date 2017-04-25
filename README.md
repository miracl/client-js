# Headless MFA Client Library

[![Master Build Status](https://travis-ci.org/miracl/mfa-client-js.svg?branch=master)](https://travis-ci.org/miracl/mfa-client-js)
[![Master Coverage Status](https://coveralls.io/repos/github/miracl/mfa-client-js/badge.svg?branch=master)](https://coveralls.io/github/miracl/mfa-client-js?branch=master)


## Requirement for build & testing

1. Nodejs
2. Mocha
3. Bower

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

```bash
var mfaOptions = {
	server: "serverUrl",
	distributor: "distributorShortCode"
}
var mfa = new Mfa(mfaOptions);
```
 1. Server - required
 2. Distributor - required
 