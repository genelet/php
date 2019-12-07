<?php
declare (strict_types = 1);

namespace Genelet;


if (PHP_VERSION_ID < 70200) {
    die('PHP version too old.');
}

/**
 * Encrypt an integer using libsodium.
 * Requires PHP 7.2+ or paragonie/sodium_compat.
 *
 * @param int $integer
 * @param string $key
 * @return string
 */
function encryptInteger(int $int, string $key): string
{
    $littleEndian = pack('V', $int);
    $nonce = random_bytes(24);
    return sodium_bin2hex(
        $nonce .
        sodium_crypto_secretbox($littleEndian, $nonce, $key)
    );
}

/**
 * Decrypt an integer using libsodium.
 * Requires PHP 7.2+ or paragonie/sodium_compat.
 *
 * @param string $ciphertext
 * @param string $key
 * @return int
 * @throws Exception
 */
function decryptInteger(string $ciphertext, string $key): int
{
    $decoded = sodium_hex2bin($ciphertext);
    if (!is_string($decoded)) {
        throw new Exception('Invalid encoding');
    }
    if (mb_strlen($decoded, '8bit') < 40) {
        throw new Exception('Message too short!');
    }
    $nonce = mb_substr($decoded, 0, 24, '8bit');
    $encrypted = mb_substr($decoded, 24, null, '8bit');
    $decrypted = sodium_crypto_secretbox_open(
        $encrypted,
        $nonce,
        $key
    );
    if (!is_string($decrypted)) {
        throw new Exception('Invalid ciphertext');
    }
    $unpacked = unpack('V', $decrypted);
    if (!is_array($unpacked)) {
        throw new Exception('Invalid value');
    }
    return (int) array_shift($unpacked);
}

/*
$key = random_bytes(32);
$int = random_int(0, 1 << 24 - 1);

$encrypted = encryptInteger($int, $key);
$decrypted = decryptInteger($encrypted, $key);

var_dump(
$int,
$encrypted,
$decrypted
);
 */
