TitaniumBackupDecrypt
=====================

Decrypts encrypted archive files from Titanium Backup for Android.

If you use this program, please let me know via a message on Github. Thanks! <br/>
https://github.com/bhafer/TitaniumBackupDecrypt

=====================

Dependencies: <br/>
&nbsp;&nbsp;&nbsp;&nbsp; http://phpseclib.sourceforge.net/ :: Install via PEAR with: <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; pear channel-discover phpseclib.sourceforge.net <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; pear install phpseclib/Crypt_AES phpseclib/Crypt_RSA

Usage: <br/>
&nbsp;&nbsp;&nbsp;&nbsp; php TitaniumBackupDecrypt &lt;archive-file&gt; <br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Will check for TB_ARCHIVE_PASSWORD environment variable or else prompt for password.
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; --OR--
&nbsp;&nbsp;&nbsp;&nbsp; php TitaniumBackupDecrypt &lt;archive-file&gt; &lt;password&gt; <br/>
Where archive-file is a file of one of the following types: <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .tar.bz2 <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .tar.gz <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .tar.lzop <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .tar <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .xml.bz2 <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .xml.gz <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .xml.lzop <br/>
&nbsp;&nbsp;&nbsp;&nbsp; .xml

Based on the file format specification information from Titanium Backup at: <br/>
&nbsp;&nbsp;&nbsp;&nbsp; https://plus.google.com/+ChristianEgger/posts/MQBmYhKDex5

=====================

Snapshot of https://plus.google.com/+ChristianEgger/posts/MQBmYhKDex5 ::

So, the file format for encrypted data backups is as follows:

"TB_ARMOR_V1" '\n' passphraseHmacKey '\n' passphraseHmacResult '\n' publicKey '\n' encryptedPrivateKey '\n' encryptedSessionKey '\n' Data <br/>

Each of the 5 "variables" (passphraseHmacKey, passphraseHmacResult, publicKey, encryptedPrivateKey, encryptedSessionKey) is stored in Base64 format without linewraps (of course) and can be decoded with: Base64.decode(passphraseHmacKey, Base64.NO_WRAP)

Then the user-supplied passphrase (String) can be verified as follows: <br/>
Mac mac = Mac.getInstance("HmacSHA1"); <br/>
mac.init(new SecretKeySpec(passphraseHmacKey, "HmacSHA1")); <br/>
byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8")); <br/>
boolean passphraseMatches = Arrays.equals(sigBytes, passphraseHmacResult);

Then the passphrase is independently hashed with SHA-1. We append [twelve] 0x00 bytes to the 160-bit result to constitute the 256-bit AES key which is used to decrypt "encryptedPrivateKey" (with an IV of [sixteen] 0x00 bytes). [Decrypt using AES-256 in CBC mode and perform PKCS5 unpadding. Note that AES-256 is equivalent to Rijndael-128 using a 256 bit key.]

Then we build the KeyPair object as follows: <br/>
KeyFactory keyFactory = KeyFactory.getInstance("RSA"); <br/>
PrivateKey privateKey2 = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey)); <br/>
PublicKey publicKey2 = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey)); <br/>
KeyPair keyPair = new KeyPair(publicKey2, privateKey2);

Then we decrypt the session key as follows: <br/>
Cipher rsaDecrypt = Cipher.getInstance("RSA/NONE/PKCS1Padding");
rsaDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate()); <br/>
ByteArrayOutputStream baos = new ByteArrayOutputStream(); <br/>
CipherOutputStream cos = new CipherOutputStream(baos, rsaDecrypt); <br/>
cos.write(encryptedSessionKey); <br/>
cos.close(); <br/>
byte[] sessionKey = baos.toByteArray();

And finally, we decrypt the data itself with the session key (which can be either a 128-bit, 192-bit or 256-bit key) and with a 0x00 IV.

While the "zero" IV is suboptimal from a security standpoint, it allows files to be encoded faster - because every little bit counts, especially when we store backups with LZO compression.

=====================

Docker usage: (until a full image is built)

First, build your own image with Docker

    docker build -t TitaniumBackupDecrypt .

Then, run as a standalone container.

You <b>MUST</b> mount the directory that holds TitaniumBackup files into the container.

Example for Windows hosts

    docker run --rm -ti -v C:\Users\Example\TitaniumBackup:/app /app/encrypted-backup.tar.gz

Example for Linux hosts

    docker run --rm -ti -v /home/example/TitaniumBackup:/app /app/encrypted-backup.tar.gz