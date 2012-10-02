crypter
=======

Simple commandline encryption tool written in Go. Example of how to use AES encryption in Go (golang). I was motivated to build this to have a base64 output so I could pass as a parameter a one time use key to my server build scripts.

Install:
--------
go install https://github.com/lateefj/crypter.git

Usage:
------

1a. First generate a key
<pre><code>crypter -gen > /tmp/test.key # Uses standard out</code></pre>

1b. Gerate key with base64 output and passing the file as a param
<pre><code>crypter -gen -b64out -out="/tmp/b64test.key"</code></pre>


2. Create some data
<pre><code>echo "This is an experiment" > /tmp/data.txt</code></pre>


3. Encrypt data with the a key
<pre><code>crypter -enc -key="/tmp/test.key" -in="/tmp/data.txt" -out="/tmp/enc_data.txt"</code></pre>


4. Decrypt data with the key
<pre><code>crypter -dec -key="/tmp/test.key" -in="/tmp/enc_data.txt" -out="/tmp/dec_data.txt"</code></pre>


Standard out will be used if there is no -out parameter

TODO:
-----
Make stdin work so could pip command together. Right now the read just support EOF
