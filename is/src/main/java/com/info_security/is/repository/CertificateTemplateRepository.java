package com.info_security.is.repository;

import com.info_security.is.model.CertificateTemplate;
import com.info_security.is.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {

    List<CertificateTemplate> findAllByOwnerOrderByUpdatedAtDesc(User owner);

    List<CertificateTemplate> findAllByIssuer_IdOrderByUpdatedAtDesc(Long issuerId);

    Optional<CertificateTemplate> findByIdAndOwner(Long id, User owner);

    boolean existsByNameAndOwner(String name, User owner);
}