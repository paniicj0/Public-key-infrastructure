package com.info_security.is.service;

import com.info_security.is.model.User;
import com.info_security.is.repository.ActivationRepository;
import com.info_security.is.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;


@Service
public class UserService  implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ActivationRepository activationRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(username);

        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        }

        User user = userOptional.get();
        return user;
    }

    @Transactional
    public void verifyUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        user.setActive(true);
        userRepository.save(user);
    }

    public void saveUser(User user){
        userRepository.save(user);
    }

    public Optional<User> findByEmail(String email) throws UsernameNotFoundException{
        return userRepository.findByEmail(email);
    }

    @Transactional
    public void verifyByUserId(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        user.setActive(true);
        userRepository.save(user);

    }


    public String getCurrentUserOrganization() {
        User currentUser = getCurrentUser();
        if (currentUser == null) {
            throw new ResponseStatusException(UNAUTHORIZED, "User not authenticated");
        }
        if (currentUser.getOrganization() == null) {
            throw new ResponseStatusException(UNAUTHORIZED, "User organization not found for user: " + currentUser.getEmail());
        }
        return currentUser.getOrganization().getName();
    }

    private User getCurrentUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("Getting current user...");

            if (authentication == null || !authentication.isAuthenticated()) {
                System.out.println("User not authenticated (no auth or not authenticated).");
                return null;
            }

            Object principal = authentication.getPrincipal();

            // 1) Ako je principal već naš entitet User
            if (principal instanceof User u) {
                // Ako org nije učitan/lazy-null, dovuci ga iz baze join-fetch upitom
                if (u.getOrganization() == null) {
                    return userRepository.findByEmailWithOrganization(u.getEmail())
                            .orElse(u); // makar vrati postojeći principal
                }
                return u;
            }

            // 2) Ako je principal UserDetails – uzmi username (email)
            String email = null;
            if (principal instanceof UserDetails ud) {
                email = ud.getUsername();
            } else if (principal instanceof String s && !"anonymousUser".equalsIgnoreCase(s)) {
                email = s;
            }

            if (email == null || email.isBlank()) {
                System.out.println("Principal has no email/username.");
                return null;
            }

            System.out.println("Looking for user with email: " + email);
            return userRepository.findByEmailWithOrganization(email)
                    .orElseGet(() -> {
                        System.out.println("User not found in database");
                        return null;
                    });

        } catch (Exception e) {
            System.err.println("Error in getCurrentUser: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }
}
