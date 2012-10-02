crypter
=======

Simple commandline encryption tool written in Go. Example of how to use AES encryption in Go (golang). I was motivated to build this to have a base64 output so I could pass as a parameter a one time use key to my server build scripts.

Install:
--------
go install https://github.com/lateefj/crypter.git

Usage:
------

1a. First generate a key
crypter -gen > /tmp/test.key # Uses standard out

1b. Gerate key with base64 output and passing the file as a param
crypter -gen -b64out -out="/tmp/b64test.key"

2. Create some data
echo "This is an experiment" > /tmp/data.txt

3. Encrypt data with the a key
crypter -enc -key="/tmp/test.key" -in="/tmp/data.txt" -out="/tmp/enc_data.txt"

4. Decrypt data with the key
crypter -dec -key="/tmp/test.key" -in="/tmp/enc_data.txt"-out="/tmp/dec_data.txt"


TODO:
-----
Make stdin work so could pip command together. Right now the read just support EOF
