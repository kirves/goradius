package goradius

import (
	"encoding/binary"
	"testing"
	"time"
	"net"
	"strings"
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

func TestDialTimeout(t *testing.T) {
	// create a UDP server that will cause a connection timeout
	timeoutHost := "127.0.0.1"
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal("Failed to open UDP server: %v", err)
	}
	defer func() {
		// ignore close errors
		udpConn.Close()
	}()
	connParts := strings.Split(udpConn.LocalAddr().String(), ":")
	timeoutPort := connParts[len(connParts) - 1]

	// set up the authenticator
	auth := AuthenticatorWithTimeout(timeoutHost, timeoutPort, secret, timeout * time.Second)

	// get the test start time
	startTime := time.Now()

	// execute the timeout test
	_, err = auth.Authenticate(user, password, nasId)

	// assert the test case passed
	if err == nil {
		t.Fatal("Failed to get the timeout error message")
	}
	expected := "Error: Server is not responding: waited 3 times 5s for an answer"
	if err.Error() != expected {
		t.Fatalf("Expected to get error message '%s', got '%s'", expected, err.Error())
	}
	execDuration := time.Now().Sub(startTime)
	if int(execDuration.Seconds()) < 14 {
		t.Fatalf("Failed to retry for expected duration; wanted at least 14 seconds, got %v", execDuration)
	}
}