package com.info_security.is.repository;

import com.info_security.is.model.CertificateModel;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateModel, Long> {
    List<CertificateModel> findAllByOrderByIdDesc();


    @Query("""
       select c from CertificateModel c
       join fetch c.issuer i
       where c.id = :id
    """)
    Optional<CertificateModel> findByIdWithIssuer(@Param("id") Long id);

    @Query("""
       select c from CertificateModel c
       where c.type = 'CA' and c.id = :id
    """)
    Optional<CertificateModel> findCAById(@Param("id") Long id);

    // za listanje po CA (issuer)
    @Query("""
       select c from CertificateModel c
       join fetch c.issuer i
       where i.id = :issuerId
    """)
    List<CertificateModel> findAllIssuedBy(@Param("issuerId") Long issuerId);

    List<CertificateModel> findAllByIssuerIdAndRevokedFalse(Long issuerId);

    boolean existsByIssuerIdAndRevokedFalse(Long issuerId);


}
