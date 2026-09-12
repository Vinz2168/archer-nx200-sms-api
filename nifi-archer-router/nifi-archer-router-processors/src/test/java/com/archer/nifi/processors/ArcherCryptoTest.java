package com.archer.nifi.processors;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * La firma RSA e l'hash MD5 sono verificati contro valori REALI catturati
 * dal traffico del router durante il reverse engineering (vedi PROTOCOL.md),
 * non solo contro vettori di test generici: questo garantisce che l'
 * implementazione Java produca esattamente gli stessi byte del client JS
 * originale, non solo un risultato "plausibile".
 */
class ArcherCryptoTest {

    @Test
    void md5HexMatchesKnownVector() {
        // Vettore di test RFC 1321 standard.
        assertEquals("900150983cd24fb0d6963f7d28e17f72", ArcherCrypto.md5Hex("abc"));
    }

    @Test
    void rsaRawEncryptMatchesRealCapturedSignature() {
        // Valori catturati da una sessione reale (nn/ee del router, hash di
        // sessione, seq+lunghezza cifrato) e la firma che il client JS
        // (js/encrypt.js, $.rsa.encrypt) ha prodotto per quell'input esatto.
        String nn = "D9FEB17A22CF0C147D4A1939A7A108B71A0F9E25AC9062084C2FD2A19FC11A8"
                + "75969B9D1124A943BD72B9CB351D3197245995CE4555B0481C55F4DBAECBCF271";
        String ee = "010001";
        String hash = "f87127542ba223ed3b29713b8fe1dfda";
        long seqParam = 862540346L;
        String expectedSign = "104cbee27e6779d44a395c23b30f47f19f0928bd835e3fff2a91d83b21241f2"
                + "8bade181d1798b248d0684daa9d8073732b476a086260c2bc516749da7da52014";

        String signInput = "h=" + hash + "&s=" + seqParam;
        String actual = ArcherCrypto.rsaRawEncrypt(signInput, nn, ee);

        assertEquals(expectedSign, actual);
    }

    @Test
    void aesRoundTripRecoversOriginalPlaintext() {
        String key = ArcherCrypto.randomToken16();
        String iv = ArcherCrypto.randomToken16();
        String plaintext = "{\"data\":{\"stack\":\"0,0,0,0,0,0\"},\"operation\":\"go\",\"oid\":\"TEST\"}";

        String cipher = ArcherCrypto.aesEncrypt(plaintext, key, iv);
        String decrypted = ArcherCrypto.aesDecrypt(cipher, key, iv);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void randomToken16HasExpectedShape() {
        String token = ArcherCrypto.randomToken16();
        assertEquals(16, token.length());
        assertEquals(true, token.chars().allMatch(Character::isDigit));
    }
}
