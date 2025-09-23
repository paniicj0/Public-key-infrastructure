package com.info_security.is.service;


import com.info_security.is.model.User;
import com.info_security.is.repository.ActivationRepository;
import com.info_security.is.repository.UserRepository;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

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
}
