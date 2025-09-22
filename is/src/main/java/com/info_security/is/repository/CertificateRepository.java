package com.info_security.is.repository;

import com.info_security.is.enums.CertifaceteType;
import com.info_security.is.model.Certificate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);
    Page<Certificate> findAllByType(CertifaceteType type, Pageable pageable);
    List<Certificate> findAllByIssuerId(Long issuerId);
}
