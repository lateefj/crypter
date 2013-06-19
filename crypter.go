package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/lateefj/crypter/capi"
	"io"
	"os"
)

var generate = flag.Bool("gen", false, "Generate a random 256 bit key")
var in = flag.String("in", "", "Input file or else read from standard in")
var out = flag.String("out", "", "Output file or it will output to standard out")
var keyPath = flag.String("key", "", "Path to the key file")
var b64out = flag.Bool("b64out", false, "Base64 the output")
var b64in = flag.Bool("b64in", false, "The input is base64")
var encMode = flag.Bool("enc", false, "Encryption mode")
var decMode = flag.Bool("dec", false, "Decryption mode")

func main() {
	flag.Parse()
	// If input file is not set then use standard in
	var fin io.Reader
	if *in == "" {
		fin = os.Stdout
	} else {
		fileIn, err := os.Open(*in)
		fin = fileIn
		defer fileIn.Close()
		if err != nil {
			fmt.Println("Could not open input file with path", out)
			fmt.Println("ERROR was: ", err)
			return
		}
	}
	// Handle base64 input
	if *b64in {
		fin = base64.NewDecoder(base64.StdEncoding, fin)
	}
	var fout io.WriteCloser
	// Write to standard out if nothing it set in the out flag
	if *out == "" {
		fout = os.Stdout
	} else {
		fileOut, err := os.Create(*out)
		defer fileOut.Close()
		fout = fileOut
		if err != nil {
			fmt.Println("FAILED: Could not create output file with path", out)
			fmt.Println("ERROR was: ", err)
			os.Exit(-1)
		}
	}
	if *b64out {
		fout = base64.NewEncoder(base64.StdEncoding, fout)
	}

	// If we are going to generate or do encryption / decryption
	if *generate {
		output := capi.GenKey(capi.AES_KEY_SIZE) // Pretty standard size
		l, err := fout.Write(output)
		if err != nil {
			fmt.Println("Could not write to file with path", out)
			fmt.Println("ERROR was: ", err)
			os.Exit(-1)
		}
		if l != len(output) {
			fmt.Println("FAILED: Did not write entire key expected", len(output), " however got ", l)
		}
	} else {
		var keyIn io.Reader
		keyFileIn, err := os.Open(*keyPath)
		keyIn = keyFileIn
		defer keyFileIn.Close()
		if err != nil {
			fmt.Println("Could not open key input file with path", keyPath)
			fmt.Println("ERROR was: ", err)
			os.Exit(-1)
		}

		block := capi.ReadKey(keyIn)
		if *encMode {
			iv := capi.GenIV()
			h := &capi.Header{int64(1), iv}
			capi.WriteHeader(h, fout)
			capi.Encrypt(block, h.IV, fin, fout)
		}
		if *decMode {
			h := capi.ReadHeader(fin)
			capi.Decrypt(block, h.IV, fin, fout)
		}
	}
}
