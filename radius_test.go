package radius

import (
	"encoding/binary"
	"testing"
)

var (
	server   string = ""
	port     string = "1812"
	secret   string = ""
	user     string = ""
	password string = ""
)

func TestConnection(t *testing.T) {
	auth := New(server, port, secret)
	if auth == nil {
		t.Fatal("Could not create authenticator object.")
	}
}

func TestNew(t *testing.T) {
	auth := New(server, port, secret)
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
	auth := New(server, port, secret)
	v := auth.generateAuthenticator()
	data, err := auth.radcrypt(v, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 16 {
		t.Fatalf("Wrong size for data: %d", len(data))
	}
}

func TestAuth(t *testing.T) {
	auth := New(server, port, secret)
	res, err := auth.Authenticate(user, password)
	if err != nil {
		t.Fatal(err)
	}
	if !res {
		t.Fatal("Could not authenticate.")
	}
}

// func TestPacketCreation(t *testing.T) {
// 	auth := New(server, port, secret)
// 	v := auth.generateAuthenticator()
// 	encpass, _ := auth.radcrypt(v, []byte(password))
// 	pkg := auth.createRequest(v, []byte(user), encpass)
// }
