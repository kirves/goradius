package goradius

import (
	"encoding/binary"
	"testing"
	"time"
)

var (
	server   string = ""
	port     string = "1812"
	secret   string = ""
	timeout  time.Duration = 5
	user     string = ""
	password string = ""
	nasId    string = ""
)

func TestConnection(t *testing.T) {
	auth := Authenticator(server, port, secret)
	if auth == nil {
		t.Fatal("Could not create authenticator object.")
	}
}

func TestAuthenticator(t *testing.T) {
	auth := Authenticator(server, port, secret)
	v := auth.generateAuthenticator()
	if binary.Size(v) != 16 {
		t.Fatal("Wrong size for authenticator")
	}
	v2 := auth.generateAuthenticator()
	for i := range v {
		if v[i] != v2[i] {
			return
		}
	}
	t.Error("The same authenticator was generated twice.")
}

func TestRadcrypt(t *testing.T) {
	auth := Authenticator(server, port, secret)
	v := auth.generateAuthenticator()
	data, err := auth.radcrypt(v, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if binary.Size(data) != 16 {
		t.Fatal("Wrong size for data")
	}
}

func TestAuth(t *testing.T) {
	auth := AuthenticatorWithTimeout(server, port, secret, timeout)
	res, err := auth.Authenticate(user, password, nasId)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Could not authenticate.")
	}
}

// func TestPacketCreation(t *testing.T) {
// 	auth := Authenticator(server, port, secret)
// 	v := auth.generateAuthenticator()
// 	encpass, _ := auth.radcrypt(v, []byte(password))
// 	pkg := auth.createRequest(v, []byte(user), encpass)
// }
