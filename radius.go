// radius package implements basic Radius client capabilities, allowing Go
// code to authenticate against a Radius server.  It is based on
// https://github.com/btimby/py-radius Python package
package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

const (
	DefaultRetries = 3                // Default number of login retries
	DefaultTimeout = 10 * time.Second // Default number of seconds before timeout
)

const (
	ACCESS_REQUEST byte = iota + 1 // id for access request packets
	ACCESS_ACCEPT                  // id for access accept packets
	ACCESS_REJECT                  // id for access reject packets
)

// The Authenticator object implements the Authenticate method to check whether
// a user can authenticate against the provided server
type Authenticator struct {
	Server  string
	Port    string
	Secret  []byte
	Retries int
	Timeout time.Duration

	// needed in order to seed it correctly and independently of consuming program
	_rand *rand.Rand
}

// This method returns a new Authenticator object, providing the server url
// and port and the secret associated to the client (registered on the server).
func New(server, port, secret string) *Authenticator {
	return &Authenticator{
		Server:  server,
		Port:    port,
		Secret:  []byte(secret),
		Retries: DefaultRetries,
		Timeout: DefaultTimeout,
		_rand:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Authenticate authenticates a user against the Radius server and returns true
// whether the user provided the correct password
func (a *Authenticator) Authenticate(username, password string) (bool, error) {
	url := fmt.Sprintf("%s:%s", a.Server, a.Port)
	conn, err := net.DialTimeout("udp", url, a.Timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	resp := make([]byte, 512)
	auth := a.generateAuthenticator()

	encpass, err := a.radcrypt(auth, []byte(password))
	if err != nil {
		return false, err
	}

	msg := a.createRequest(auth, []byte(username), encpass)

	var rerr error
	for i := 0; i < a.Retries; i++ {
		conn.Write(msg)
		ch := make(chan error, 1)
		go func(ch chan error) {
			l, err := conn.Read(resp)
			if err == nil {
				resp = resp[:l] // this ensures that parseResponse deals with a actual package length
			}
			ch <- err
		}(ch)

		select {
		case err := <-ch:
			if err != nil {
				return false, err
			} else {
				return a.parseResponse(auth, resp)
			}
		case <-time.After(a.Timeout):
			rerr = fmt.Errorf("timed out while waiting for an answer (retries: %d)", i+1)
		}
	}
	return false, rerr
}

func (a *Authenticator) generateAuthenticator() []byte {
	v := [16]byte{}
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(v[i*4:(i+1)*4], a._rand.Uint32())
	}
	return v[:]
}

func (a *Authenticator) radcrypt(auth, passwd []byte) ([]byte, error) {
	if len(passwd) > 128 {
		return nil, fmt.Errorf("password exceeds maximum of 128 bytes")
	}

	// Pad the passwd to a multiple of 16 octects
	text := make([]byte, (len(passwd)+15)&-16)
	copy(text, passwd)

	result := []byte{}
	last := append([]byte{}, auth...)
	for len(text) > 0 {
		hash := md5.Sum(append(a.Secret, last...))
		for i := range hash {
			result = append(result, hash[i]^text[i])
		}
		last = result[len(result)-16:]
		text = text[16:]
	}
	return result, nil
}

func (a *Authenticator) createRequest(auth, uname, encpass []byte) []byte {
	buf := new(bytes.Buffer)
	type requestHeader struct {
		Type     byte
		Id       byte
		MsgLen   uint16
		Auth     [16]byte
		Type2    byte
		UnameLen byte
	}

	var tmpAuth [16]byte
	copy(tmpAuth[:], auth)

	req := requestHeader{
		ACCESS_REQUEST,
		byte(a._rand.Int() % 256),
		uint16(len(uname) + len(encpass) + 24),
		tmpAuth,
		1,
		byte(len(uname) + 2),
	}

	binary.Write(buf, binary.BigEndian, req)
	buf.Write(uname)
	buf.WriteByte(2)
	buf.WriteByte(byte(len(encpass) + 2))
	buf.Write(encpass)
	return buf.Bytes()
}

func (a *Authenticator) parseResponse(auth, resp []byte) (bool, error) {
	m := md5.Sum(bytes.Join([][]byte{resp[0:4], auth, resp[20:], a.Secret}, nil))
	if bytes.Compare(resp[4:20], m[:]) != 0 {
		return false, fmt.Errorf("forged or corrupted answer")
	}

	if resp[0] == ACCESS_ACCEPT {
		return true, nil
	} else {
		return false, nil
	}
}
