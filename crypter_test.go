package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestWriteReadHeader(t *testing.T) {
	h := &header{}
	h.Version = int64(1)
	h.IV = genIV()
	b := bytes.NewBuffer(make([]byte, 0))
	writeHeader(h, b)

	nh := readHeader(b)
	if h.Version != nh.Version {
		t.Errorf("Expected version to be", h.Version, "but was", nh.Version)
	}

	if !bytes.Equal(h.IV, nh.IV) {
		t.Errorf("Expected IV to be equal but it is not")
	}
}
func TestWriteEncryptDecrypt(t *testing.T) {
	h := &header{}
	h.Version = int64(1)
	h.IV = genIV()
	data := []byte("this is a test used to see if encryption and decryption is working right. I wonder...")
	block, err := aes.NewCipher(genKey(32))
	if err != nil {
		t.Errorf("Error trying to create cipher", err)
	}
	in := bytes.NewBuffer(make([]byte, 0))
	out := bytes.NewBuffer(make([]byte, 0))
	in.Write(data)
	encrypt(block, h.IV, in, out)
	e := out.Bytes()
	if bytes.Equal(data, e) {
		t.Errorf(fmt.Sprint("Encryption did not happen bytes are the same expected '", string(data), "' to not eqaul '", string(e), "'"))
	}
	in.Reset()
	decrypt(block, h.IV, out, in)
	d := in.Bytes()
	if !bytes.Equal(d, data) {
		t.Errorf(fmt.Sprint("Decryptiong did not happen bytes are the different expected '", string(data), "' but got '", string(d), "'", " compare says: ", bytes.Compare(d, data)))
	}
}
