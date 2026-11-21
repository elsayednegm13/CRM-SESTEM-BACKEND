<?php

// Temporary loopback TLS material lives only in this round's external runtime.
$runtime = $argv[1] ?? '';
if (!is_dir($runtime) || !str_contains(realpath($runtime) ?: '', 'f06-team01-')) {
    throw new RuntimeException('Unexpected runtime directory');
}
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
if ($key === false) {
    throw new RuntimeException('TLS key generation failed');
}
$csr = openssl_csr_new(['commonName' => 'tenant-a.f06i03.localhost'], $key, ['digest_alg' => 'sha256']);
$cert = $csr !== false ? openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']) : false;
if ($cert === false || !openssl_pkey_export($key, $keyPem) || !openssl_x509_export($cert, $certPem)) {
    throw new RuntimeException('TLS certificate generation failed');
}
file_put_contents($runtime.DIRECTORY_SEPARATOR.'team01-key.pem', $keyPem);
file_put_contents($runtime.DIRECTORY_SEPARATOR.'team01-cert.pem', $certPem);
echo "SYNTHETIC_LOOPBACK_TLS_CERT=CREATED\n";
