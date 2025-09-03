package com.info_security.is.enums;

public enum UserRole {
    ADMIN,   // pravi root CA i CA korisnike
    CA,      // "Certificate Authority" korisnik – izdaje intermediate i EE sertifikate u okviru svoje organizacije/lanca
    USER     // može da registruje nalog, šalje CSR ili traži auto-generisan sertifikat za sebe
}
