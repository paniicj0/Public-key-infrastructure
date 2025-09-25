package com.info_security.is.repository;

import com.info_security.is.enums.CertifaceteType;
import com.info_security.is.model.CertificateModel;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateModel, Long> {
    Optional<CertificateModel> findBySerialNumber(String serialNumber);
    Page<CertificateModel> findAllByType(CertifaceteType type, Pageable pageable);
    List<CertificateModel> findAllByIssuerId(Long issuerId);
}
