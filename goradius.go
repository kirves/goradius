// Package goradius implements basic Radius client capabilities, allowing Go code to authenticate against a Radius server.
// It is based on https://github.com/btimby/py-radius Python package
package goradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"
)

const (
	// AccessRequest packet id
	AccessRequest = iota + 1
	// AccessAccept packet id
	AccessAccept
	// AccessReject packet id
	AccessReject

	// RETRIES is the number of login retries
	RETRIES = 3
)

// The AuthenticatorT object implements the Authenticate method to check whether a user can authenticate against the provided server
type AuthenticatorT struct {
	server  string
	port    string
	secret  []byte
	timeout time.Duration
}

// Authenticator method returns a new AuthenticatorT object, providing the server url and port and the secret
// associated to the client (registered on the server).
func Authenticator(server, port, secret string) *AuthenticatorT {
	return &AuthenticatorT{server, port, []byte(secret), 10 * time.Second}
}

// AuthenticatorWithTimeout method returns a new AuthenticatorT object, providing the server url, the port, the secret
// and a timeout associated to the client (registered on the server).
func AuthenticatorWithTimeout(server, port, secret string, timeout time.Duration) *AuthenticatorT {
	return &AuthenticatorT{server, port, []byte(secret), timeout}
}

// Authenticate authenticates a user against the Radius server and returns true whether the user provided the correct password
// If nasId is empty this attribute won't be included in request.
func (a *AuthenticatorT) Authenticate(username, password, nasID string) (bool, error) {
	url := fmt.Sprintf("%s:%s", a.server, a.port)
	conn, err := net.DialTimeout("udp", url, a.timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	auth := a.generateAuthenticator()
	encpass, err := a.radcrypt(auth, []byte(password))
	if err != nil {
		return false, err
	}

	req := a.createRequest(auth, []byte(username), encpass, []byte(nasID))

	for i := 0; i < RETRIES; i++ {
		conn.Write(req)
		var resp = make([]byte, 512)
		ch := make(chan int, 1)
		eCh := make(chan error, 1)
		go func(ch chan int, eCh chan error) {
			_, err := conn.Read(resp)
			if err != nil {
				eCh <- err
			} else {
				ch <- 1
			}
		}(ch, eCh)

		select {
		case <-ch:
			return a.parseResponse(resp, auth)
		case err := <-eCh:
			return false, err
		case <-time.After(a.timeout):
		}
	}
	return false, fmt.Errorf("Error: Server is not responding: waited %d times %v for an answer", RETRIES, a.timeout)
}

func (a *AuthenticatorT) generateAuthenticator() []byte {
	v := make([]byte, 16)
	for i := range v {
		v[i] = byte(rand.Int())
	}
	return v
}

func (a *AuthenticatorT) radcrypt(auth, passwd []byte) ([]byte, error) {
	// Pad the passwd to a multiple of 16 octects
	text := make([]byte, 16*int(math.Ceil(float64(binary.Size(passwd))/16.0)))
	copy(text, passwd)
	for i := binary.Size(passwd); i < len(text); i++ {
		text[i] = 0
	}
	if len(text) > 128 {
		return nil, errors.New("Password exceeds maximum of 128 bytes")
	}

	var result = make([]byte, 0)
	last := make([]byte, len(auth))
	copy(last, auth)
	for len(text) > 0 {
		hash := md5.Sum(bytes.Join([][]byte{a.secret, last}, nil))
		for i := range hash {
			result = append(result, hash[i]^text[i])
		}
		last = result[len(result)-16:]
		text = text[16:]
	}
	return result, nil
}

func (a *AuthenticatorT) createRequest(auth, uname, encpass, nasId []byte) []byte {
	buf := new(bytes.Buffer)
	type requestHeader struct {
		Type     int8
		ID       int8
		MsgLen   uint16
		Auth     [16]byte
		Type2    int8
		UnameLen int8
	}

	var tmpAuth [16]byte
	for i := range tmpAuth {
		tmpAuth[i] = auth[i]
	}

	var nasIdInHeader int
	if len(nasId) > 0 {
		nasIdInHeader = len(nasId) + 2
	} else {
		nasIdInHeader = 0
	}

	req := requestHeader{
		AccessRequest,
		int8(rand.Int() % 256),
		uint16(len(uname) + len(encpass) + nasIdInHeader + 24),
		tmpAuth,
		1,
		int8(len(uname) + 2),
	}

	binary.Write(buf, binary.BigEndian, req)
	buf.Write(uname)
	binary.Write(buf, binary.BigEndian, int8(2))
	binary.Write(buf, binary.BigEndian, int8(len(encpass)+2))
	buf.Write(encpass)
	if len(nasId) > 0 {
		binary.Write(buf, binary.BigEndian, int8(32))
		binary.Write(buf, binary.BigEndian, int8(len(nasId)+2))
		buf.Write(nasId)
	}
	return buf.Bytes()
}

func (a *AuthenticatorT) parseResponse(resp []byte, auth []byte) (bool, error) {
	// ignore everything after the specified length
	l := binary.BigEndian.Uint16(resp[2:4])

	checkauth := resp[4:20]
	m := md5.Sum(bytes.Join([][]byte{resp[0:4], auth, resp[20:l], a.secret}, nil))
	if bytes.Compare(checkauth, m[:]) != 0 {
		return false, errors.New("Forged or corrupted answer")
	}
	if int64(resp[0]) == AccessAccept {
		return true, nil
	}
	return false, nil
}
