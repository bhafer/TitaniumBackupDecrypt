<?php
// ---------------------------
// TitaniumBackupDecrypt
// https://github.com/bhafer/TitaniumBackupDecrypt
//
// Decrypts encrypted archive files from Titanium Backup for Android.
//
// Dependencies:
//     http://phpseclib.sourceforge.net/ :: Install via PEAR with:
//         pear channel-discover phpseclib.sourceforge.net
//         pear install phpseclib/Crypt_AES phpseclib/Crypt_RSA
//
// Usage:
//     php TitaniumBackupDecrypt <archive-file>
// Where archive-file is a file of one of the following types:
//     .tar.bz2
//     .tar.gz
//     .tar.lzop
//     .tar
//     .xml.bz2
//     .xml.gz
//     .xml.lzop
//     .xml
//
// Based on file format specification information from Titanium Backup at:
//     https://plus.google.com/+ChristianEgger/posts/MQBmYhKDex5
//
// ---------------------------
//
// The MIT License (MIT)
//
// Copyright (c) 2014 Brian T. Hafer
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// ---------------------------

require_once('Crypt/AES.php');
require_once('Crypt/RSA.php');

define('TB_BUFFER_SIZE', 128 * 2048);

function pkcs5_unpad($text) {
    $pad = ord($text{strlen($text)-1});
    if ($pad > strlen($text)) return false;
    if (strspn($text, chr($pad), strlen($text) - $pad) != $pad) return false;
    return substr($text, 0, -1 * $pad);
}

if (count($argv) != 2) {
    echo "No archive file specified.\nUsage:\n     php TitaniumBackupDecrypt <archive-file>\n";
    exit(1);
}

$filenameIn = $argv[1];
$fileIn = fopen($filenameIn, 'rb');
if ($fileIn === false) {
    echo "File not found: $filenameIn";
    exit(1);
}

// Determine input file type.
$filename = basename($argv[1]);
if (substr($filename, -strlen('.tar.gz')) == '.tar.gz') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.tar.gz') . '-decrypted.tar.gz';
} else if (substr($filename, -strlen('.tar.bz2')) == '.tar.bz2') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.tar.bz2') . '-decrypted.tar.bz2';
} else if (substr($filename, -strlen('.tar.lzop')) == '.tar.lzop') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.tar.lzop') . '-decrypted.tar.lzop';
} else if (substr($filename, -strlen('.tar')) == '.tar') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.tar') . '-decrypted.tar';
} else if (substr($filename, -strlen('.xml.gz')) == '.xml.gz') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.xml.gz') . '-decrypted.xml.gz';
} else if (substr($filename, -strlen('.xml.bz2')) == '.xml.bz2') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.xml.bz2') . '-decrypted.xml.bz2';
} else if (substr($filename, -strlen('.xml.lzop')) == '.xml.lzop') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.xml.lzop') . '-decrypted.xml.lzop';
} else if (substr($filename, -strlen('.xml')) == '.xml') {
    $filenameOut = dirname($argv[1]) . DIRECTORY_SEPARATOR . basename($argv[1], '.xml') . '-decrypted.xml';
} else {
    echo "Unknown archive file type.\n";
    exit(1);
}

$header = fgets($fileIn, 64);
$header = rtrim($header, "\n");
echo "File type: $header \n";
if ($header != "TB_ARMOR_V1") {
    echo "Unsupported file format. Expected: \"TB_ARMOR_V1\".";
    exit(1);
}

$passphraseHmacKey = fgets($fileIn, 1024);
$passphraseHmacKey = rtrim($passphraseHmacKey, "\n");
//echo "Passphrase HMAC Key: $passphraseHmacKey \n";
$passphraseHmacKey = base64_decode($passphraseHmacKey, true);
if ($passphraseHmacKey === false) {
    echo "Invalid Passphrase HMAC Key.";
    exit(1);
}

$passphraseHmacResult = fgets($fileIn, 1024);
$passphraseHmacResult = rtrim($passphraseHmacResult, "\n");
//echo "Passphrase HMAC Result: $passphraseHmacResult \n";
$passphraseHmacResult = base64_decode($passphraseHmacResult, true);
if ($passphraseHmacResult === false) {
    echo "Invalid Passphrase HMAC Result.";
    exit(1);
}

$publicKey = fgets($fileIn, 1024);
$publicKey = rtrim($publicKey, "\n");
//echo "Public Key: $publicKey \n";
$publicKey = base64_decode($publicKey, true);
if ($publicKey === false) {
    echo "Invalid Public Key.";
    exit(1);
}

$encryptedPrivateKey = fgets($fileIn, 4096);
$encryptedPrivateKey = rtrim($encryptedPrivateKey, "\n");
//echo "Encrypted Private Key: $encryptedPrivateKey \n";
$encryptedPrivateKey = base64_decode($encryptedPrivateKey, true);
if ($encryptedPrivateKey === false) {
    echo "Invalid Encrypted Private Key.";
    exit(1);
}

$encryptedSessionKey = fgets($fileIn, 1024);
$encryptedSessionKey = rtrim($encryptedSessionKey, "\n");
//echo "Encrypted Session Key: $encryptedSessionKey \n";
$encryptedSessionKey = base64_decode($encryptedSessionKey, true);
if ($encryptedSessionKey === false) {
    echo "Invalid Encrypted Session Key.";
    exit(1);
}

// @TODO Would be much better if password were hidden on the command line.
$prompt = "Enter encryption passphrase: ";
if (PHP_OS == 'WINNT') {
  echo $prompt;
  $passphrase = stream_get_line(STDIN, 1024, PHP_EOL);
} else {
  $passphrase = readline($prompt);
}

if ($passphraseHmacResult != hash_hmac('sha1', $passphrase, $passphraseHmacKey, true)) {
    echo "Supplied passphrase not valid for encrypted file.";
    exit(1);
}

$aesKey = sha1($passphrase, true) . "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
if (strlen($aesKey) * 8 != 256) {
    echo "Error generating AES key from supplied passphrase.";
    exit(1);
}

$aesCipher = new Crypt_AES(CRYPT_AES_MODE_CBC);
$aesCipher->setKey($aesKey);
$aesCipher->setIV("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
$decryptedPrivateKey = $aesCipher->decrypt($encryptedPrivateKey);
// Other ways to do this:
// $decryptedPrivateKey = openssl_decrypt($encryptedPrivateKey, 'aes-256-cbc', $aesKey, true, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
// $decryptedPrivateKey = pkcs5_unpad(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $aesKey, $encryptedPrivateKey, MCRYPT_MODE_CBC, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"));
//echo "Decrypted Private Key: " . base64_encode($decryptedPrivateKey) . " \n";

$rsaCipher = new Crypt_RSA();
$rsaCipher->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
$rsaCipher->loadKey($decryptedPrivateKey);
$decryptedSessionKey = $rsaCipher->decrypt($encryptedSessionKey);
//echo "Decrypted Session Key: " . base64_encode($decryptedSessionKey) . " \n";
echo "Session Key Length: " . strlen($decryptedSessionKey) * 8 . " \n";

// Create output file.
$fileOut = fopen($filenameOut, 'wb');
echo "Writing file: $filenameOut\n";

// Setup cipher for continuous buffering and copy between files.
$aesCipher->setKey($decryptedSessionKey);
$aesCipher->enableContinuousBuffer();
$aesCipher->disablePadding();
while (!feof($fileIn)) {
    fwrite($fileOut, $aesCipher->decrypt(fread($fileIn, TB_BUFFER_SIZE)));
}

fclose($fileIn);
fclose($fileOut);

echo "Done.";

?>
