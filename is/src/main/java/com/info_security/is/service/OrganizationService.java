package com.info_security.is.service;

import com.info_security.is.model.Organization;
import com.info_security.is.repository.OrganizationRepository;
import jakarta.transaction.Transactional;
import org.springframework.stereotype.Service;

@Service
public class OrganizationService {
    private final OrganizationRepository repo;

    public OrganizationService(OrganizationRepository repo) {
        this.repo = repo;
    }

    @Transactional
    public Organization findOrCreateByName(String name) {
        String trimmed = name == null ? "" : name.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Organization name is required");
        }
        return repo.findByNameIgnoreCase(trimmed)
                .orElseGet(() -> {
                    Organization o = new Organization();
                    o.setName(trimmed);
                    return repo.save(o);
                });
    }
}

