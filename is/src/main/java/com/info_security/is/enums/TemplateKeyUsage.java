package com.info_security.is.enums;

public enum TemplateKeyUsage {
    DIGITAL_SIGNATURE,        // digitalSignature
    CONTENT_COMMITMENT,       // nonRepudiation
    KEY_ENCIPHERMENT,         // keyEncipherment
    DATA_ENCIPHERMENT,        // dataEncipherment
    KEY_AGREEMENT,            // keyAgreement
    KEY_CERT_SIGN,            // keyCertSign
    CRL_SIGN,                 // cRLSign
    ENCIPHER_ONLY,            // encipherOnly
    DECIPHER_ONLY             // decipherOnly
}