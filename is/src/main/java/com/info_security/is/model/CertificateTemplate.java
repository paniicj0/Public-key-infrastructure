package com.info_security.is.model;

import com.info_security.is.enums.TemplateEKU;
import com.info_security.is.enums.TemplateKeyUsage;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "certificate_templates",
        uniqueConstraints = @UniqueConstraint(columnNames = {"name", "owner_user_id"}))
@Getter
@Setter
public class CertificateTemplate {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        // Naziv šablona (jedinstven u okviru vlasnika/CA korisnika)
        @Column(nullable = false, length = 128)
        private String name;

        // CA issuer koji će izdavati sertifikate na osnovu ovog šablona
        @ManyToOne(optional = false, fetch = FetchType.LAZY)
        @JoinColumn(name = "issuer_id")
        private CertificateModel issuer;

        // Regex za CN (npr. .*\\.ftn\\.com)
        @Column(name = "cn_regex", length = 512)
        private String cnRegex;

        // Regex za SAN (wildcard regex za hostove/mailove itd.)
        @Column(name = "san_regex", length = 512)
        private String sanRegex;

        // Maksimalno trajanje u danima
        @Column(name = "ttl_days", nullable = false)
        private Integer ttlDays;

        // Podrazumevani KeyUsage i EKU
        @ElementCollection(fetch = FetchType.EAGER)
        @CollectionTable(name = "template_key_usages", joinColumns = @JoinColumn(name = "template_id"))
        @Enumerated(EnumType.STRING)
        @Column(name = "key_usage", length = 32, nullable = false)
        private List<TemplateKeyUsage> keyUsage;

        @ElementCollection(fetch = FetchType.EAGER)
        @CollectionTable(name = "template_ext_key_usages", joinColumns = @JoinColumn(name = "template_id"))
        @Enumerated(EnumType.STRING)
        @Column(name = "ext_key_usage", length = 32, nullable = false)
        private List<TemplateEKU> extendedKeyUsage;

        // Vlasnik šablona (CA korisnik)
        @ManyToOne(optional = false, fetch = FetchType.LAZY)
        @JoinColumn(name = "owner_user_id")
        private User owner;

        // Audit polja (opciono)
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;

        @PrePersist
        void onCreate() { createdAt = LocalDateTime.now(); updatedAt = createdAt; }

        @PreUpdate
        void onUpdate() { updatedAt = LocalDateTime.now(); }
}
