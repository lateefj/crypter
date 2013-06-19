package lib

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func TestWriteReadHeader(t *testing.T) {
	h := &Header{}
	h.Version = int64(1)
	h.IV = GenIV()
	b := bytes.NewBuffer(make([]byte, 0))
	WriteHeader(h, b)

	nh := ReadHeader(b)
	if h.Version != nh.Version {
		t.Errorf("Expected version to be", h.Version, "but was", nh.Version)
	}

	if !bytes.Equal(h.IV, nh.IV) {
		t.Errorf("Expected IV to be equal but it is not")
	}
}
func TestWriteEncryptDecrypt(t *testing.T) {
	h := &Header{}
	h.Version = int64(1)
	h.IV = GenIV()
	data := []byte("this is a test for bytes...")
	block, err := aes.NewCipher(GenKey(32))
	if err != nil {
		t.Errorf("Error trying to create cipher", err)
	}
	in := bytes.NewBuffer(make([]byte, 0))
	out := bytes.NewBuffer(make([]byte, 0))
	in.Write(data)
	Encrypt(block, h.IV, in, out)
	e := out.Bytes()
	println("Length of encrypted bytes is ", len(e))
	if bytes.Equal(data, e) {
		t.Errorf(fmt.Sprint("Encryption did not happen bytes are the same expected '", string(data), "' to not eqaul '", string(e), "'"))
	}
	in.Reset()
	Decrypt(block, h.IV, out, in)
	d := make([]byte, len(data))
	in.Read(d)
	if !bytes.Equal(d, data) {
		println("OK length of d is ", len(d), " and data length is ", len(data))
		t.Errorf(fmt.Sprint("Decryptiong did not happen bytes are the different expected '", string(data), "' but got '", string(d), "'", " compare says: ", bytes.Compare(d, data)))
	}
}
