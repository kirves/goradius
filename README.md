goradius
========

[![Build Status](https://travis-ci.org/kirves/goradius.png?branch=master)](https://travis-ci.org/kirves/goradius) [![GoDoc](https://godoc.org/github.com/kirves/goradius?status.png)](http://godoc.org/github.com/kirves/goradius)


Description
-----------

`goradius` package implements basic Radius client capabilities, allowing Go code ti authenticate against a Radius server.
It is based on https://github.com/btimby/py-radius python package

Installation
------------

To install this package simply:

	go get github.com/kirves/goradius

Test
----

Before testing `goradius` fill the necessary data in the goradius_test.go file (server url, secret, username and password to test the client).

After that, simply run:

	go test github.com/kirves/goradius

Example
-------

To authenticate a user simply create a new `Authenticator` object using server information and the secret associated to your client

	auth := radius.New(server_url, server_port, secret)

And try to authenticate a user:

	ok, err := auth.Authenticate(username, password)
	if err != nil {
		panic(err)
	}
	if ok {
		// user successfully authenticated
	}

License
-------------

`goradius` is released under the MIT license. See [LICENSE](https://github.com/kirves/goradius/blob/master/LICENSE).
