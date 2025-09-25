package com.info_security.is.repository;

import com.info_security.is.model.Activation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ActivationRepository extends JpaRepository<Activation, Long> {

    @Query("SELECT a FROM Activation a WHERE a.user.id = :user_id")
    Optional<Activation> findByUserId(@Param("user_id") Long userId);

    Optional<Activation> findByTokenHash(String tokenHash);
}
