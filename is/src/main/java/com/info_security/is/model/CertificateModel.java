package com.info_security.is.model;

import com.info_security.is.enums.CertifaceteType;
import com.info_security.is.enums.RevocationReason;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Entity
@Table(name = "certificates")
public class CertificateModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private CertifaceteType type; // ROOT, CA, EE

    @Column(nullable = false, unique = true, length = 512) // <-- povećano na 512
    private String serialNumber;

    @Column(nullable = false, columnDefinition = "TEXT")   // <-- eksplicitno tražimo TEXT
    private String certificatePem; // X.509 u PEM formatu

    @Column(columnDefinition = "TEXT")                    // <-- eksplicitno tražimo TEXT
    private String privateKeyEnc;                         // enkriptovani privatni ključ (Base64)

    private LocalDateTime notBefore;
    private LocalDateTime notAfter;

    @ManyToOne
    private CertificateModel issuer; // null za ROOT

    private boolean revoked = false;

    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private RevocationReason revocationReason;

    private LocalDateTime revokedAt;
    private Long revokedByUserId;
}
