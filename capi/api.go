package lib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strconv"
)

const (
	DATA_FILE_VERSION = 1
	VERSION_BYTES     = 1
	IV_BYTES          = 16
	AES_KEY_SIZE      = 32
)

type Header struct {
	Version int64
	IV      []byte
}

func WriteHeader(h *Header, file io.Writer) {
	data := bytes.NewBuffer(make([]byte, 0))
	data.Write([]byte(strconv.FormatInt(h.Version, 10)))
	data.Write(h.IV)
	dataSize := data.Len()
	if dataSize != VERSION_BYTES+IV_BYTES {
		fmt.Println("ERROR: got unexpected header length of", dataSize)
	}
	s, err := data.WriteTo(file)
	if err != nil {
		fmt.Println("ERROR: In WriteTo of buffer", err)
	}
	if int(s) != dataSize {
		fmt.Println("ERROR: Expected total header bytes written to be", dataSize, " however it was ", s)
	}
}

func ReadHeader(file io.Reader) *Header {
	h := &Header{}
	// First get version of 
	data := make([]byte, VERSION_BYTES)
	s, err := file.Read(data)
	if s != VERSION_BYTES {
		fmt.Println("ERROR: Version expected to have read", VERSION_BYTES, " but ony read ", s)
	}
	h.Version, err = strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		fmt.Println("ERROR: Could not parse version in file format")
		return nil
	}

	if err != nil {
		fmt.Println("ERROR: Could not parse file size in file format")
		return nil
	}
	// Now get the vi
	data = make([]byte, IV_BYTES)
	s, err = file.Read(data)
	if s != IV_BYTES {
		fmt.Println("ERROR: File size expected to have read", IV_BYTES, " but ony read ", s)
	}
	h.IV = data

	return h
}

// Generate a random key that takes the size as a param
func GenKey(size int) []byte {
	key := make([]byte, size)
	n, err := io.ReadFull(rand.Reader, key)
	if n != len(key) || err != nil {
		fmt.Println("Could not generate random key\nERROR:", err)
		panic(err)
	}
	return key
}

// Wrapper around random key generator
func GenIV() []byte {
	return GenKey(16)
}

// This takes an io.Reader to load the key. Expecting this to be from a file or stdin
func ReadKey(in io.Reader) cipher.Block {
	key := make([]byte, AES_KEY_SIZE)
	r, err := in.Read(key)
	if err != nil {
		fmt.Println("FAILED: Trying to read key file", err)
		os.Exit(-1)
	}
	if r != AES_KEY_SIZE {
		fmt.Println("FAILED: Expected to be able to read", AES_KEY_SIZE, "bytes but read", r)
		os.Exit(-1)
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("FAILED: to create cipher: ", err)
		os.Exit(-1)
	}
	return c
}

// Based on the block read the input and write ecrypted to the output
func Encrypt(block cipher.Block, iv []byte, in io.Reader, out io.Writer) {
	stream := cipher.NewCBCEncrypter(block, iv)
	for {
		plain := make([]byte, block.BlockSize())
		_, err := in.Read(plain)
		if err != nil && err != io.EOF {
			fmt.Println("FAILED: Encrypter to read input fil: ", err)
			os.Exit(-1)
		}
		cryptic := make([]byte, block.BlockSize())
		stream.CryptBlocks(cryptic, plain)
		out.Write(cryptic)
		if err == io.EOF {
			break
		}
	}
}

func Decrypt(block cipher.Block, iv []byte, in io.Reader, out io.Writer) {
	stream := cipher.NewCBCDecrypter(block, iv)
	for {
		cryptic := make([]byte, block.BlockSize())
		s, err := in.Read(cryptic)
		if err != nil && err != io.EOF {
			fmt.Println("FAILED: Decrypter to read input file: ", err)
			os.Exit(-1)
		}
		plain := make([]byte, block.BlockSize())
		stream.CryptBlocks(plain, cryptic)
		out.Write(plain[:s]) // Don't need to write out non ready blocks
		if err == io.EOF {
			break
		}
	}
}
