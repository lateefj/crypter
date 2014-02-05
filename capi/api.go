package capi

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
  "crypto/rand"
  "errors"
  "fmt"
  "io"
  "strconv"
)

const (
  // DATA_FILE_VERSION is the current version of the file
  DATA_FILE_VERSION = 1
  // VERSION_BYTES size in bytes of the version number
  VERSION_BYTES = 1
  // IV_BYTES initial vector bytes size
  IV_BYTES = 16
  // AES keys size in bytes
  AES_KEY_SIZE = 32
  // VERSION is the int64 of the version
  VERSION = int64(1)
)

// Header [...] this is the first couple bytes of the file. It contains the Version int64 number and the initial vector. The Version this is design to support different versions of the software how the file is parsed. The initial vector to start encryption has to exist.
type Header struct {
  Version int64
  IV      []byte
}

// NewHeader ... Creates a new header for an encrypted file.
func NewHeader(iv []byte) *Header {
  return &Header{VERSION, iv}
}

// WriteHeader ... writes a header to an io.Writer
func WriteHeader(h *Header, file io.Writer) error {
  data := bytes.NewBuffer(make([]byte, 0))
  data.Write([]byte(strconv.FormatInt(h.Version, 10)))
  data.Write(h.IV)
  dataSize := data.Len()
  if dataSize != VERSION_BYTES+IV_BYTES {
    msg := fmt.Sprintf("ERROR: got unexpected header length of %s", dataSize)
    return errors.New(msg)
  }
  s, err := data.WriteTo(file)
  if err != nil {
    fmt.Printf("ERROR: In WriteTo of buffer %s\n", err)
    return err
  }
  if int(s) != dataSize {
    msg := fmt.Sprintf("ERROR: Expected total header bytes written to be %d however it was %d", dataSize, s)
    return errors.New(msg)
  }
  return nil
}

// ReadHeader ... Reads a header from a io.Reader
func ReadHeader(file io.Reader) (*Header, error) {
  h := &Header{}
  // First get version of
  data := make([]byte, VERSION_BYTES)
  s, err := file.Read(data)
  if s != VERSION_BYTES {
    fmt.Println("ERROR: Version expected to have read", VERSION_BYTES, " but ony read ", s)
  }
  h.Version, err = strconv.ParseInt(string(data), 10, 64)
  if err != nil {
    return nil, err
  }

  // Now get the vi
  data = make([]byte, IV_BYTES)
  s, err = file.Read(data)
  if s != IV_BYTES {
    msg := fmt.Sprintf("ERROR: File size expected to have read %d but ony read %d", IV_BYTES, s)
    return nil, errors.New(msg)
  }
  h.IV = data
  return h, nil
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

// ReadKey ... This takes an io.Reader to load the key. Expecting this to be from a file or stdin
func ReadKey(in io.Reader) (cipher.Block, error) {
  key := make([]byte, AES_KEY_SIZE)
  r, err := in.Read(key)
  if err != nil {
    fmt.Println("FAILED: Trying to read key file", err)
    return nil, err
  }
  if r != AES_KEY_SIZE {
    msg := fmt.Sprintf("FAILED: Expected to be able to read %d bytes but read %d", AES_KEY_SIZE, r)
    return nil, errors.New(msg)
  }
  c, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }
  return c, nil
}

// Encrypt ... Based on the block read the input and write ecrypted to the output
func Encrypt(block cipher.Block, iv []byte, in io.Reader, out io.Writer) error {
  stream := cipher.NewCBCEncrypter(block, iv)
  for {
    plain := make([]byte, block.BlockSize())
    _, err := in.Read(plain)
    if err != nil && err != io.EOF {
      fmt.Println("FAILED: Encrypter to read input file: ", err)
      return err
    }
    cryptic := make([]byte, block.BlockSize())
    stream.CryptBlocks(cryptic, plain)
    _, oErr := out.Write(cryptic)
    if err == io.EOF {
      break
    }
    if oErr != nil {
      return oErr
    }
  }
  return nil
}

// Decrypt ... Decrypt based on the block read
func Decrypt(block cipher.Block, iv []byte, in io.Reader, out io.Writer) error {
  stream := cipher.NewCBCDecrypter(block, iv)
  for {
    cryptic := make([]byte, block.BlockSize())
    s, err := in.Read(cryptic)
    if err != nil && err != io.EOF {
      return err
    }
    plain := make([]byte, block.BlockSize())
    stream.CryptBlocks(plain, cryptic)
    _, oError := out.Write(plain[:s]) // Don't need to write out non ready blocks
    if err == io.EOF {
      break
    }
    if oError != nil {
      return oError
    }
  }
  return nil
}
