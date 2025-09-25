package com.info_security.is.repository;

import com.info_security.is.model.Organization;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OrganizationRepository extends JpaRepository<Organization, Long> {
    Optional<Organization> findByNameIgnoreCase(String name);
}
