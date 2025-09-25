package com.info_security.is.service;

import com.info_security.is.model.Activation;
import com.info_security.is.model.User;
import com.info_security.is.repository.ActivationRepository;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.time.LocalDateTime;


@Service
public class ActivationService {

    @Autowired private ActivationRepository activationRepository;
    @Autowired private JavaMailSender mailSender;

    public Activation save(Activation activation) { return activationRepository.save(activation); }

    public Activation findOne(Long id){ return activationRepository.findById(id).orElse(null); }

    public Activation getActivationByUserId(Long userId) {
        return activationRepository.findByUserId(userId)
                .orElseThrow(() -> new EntityNotFoundException("Activation not found for User with ID: " + userId));
    }

    private static String generateRawToken() {
        byte[] buf = new byte[32];
        new java.security.SecureRandom().nextBytes(buf);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    // ⬇⬇⬇ učini public da ga kontroler može pozvati
    public String sha256Hex(String input) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public void createActivationAndSendEmail(User user)
            throws MessagingException, UnsupportedEncodingException {

        activationRepository.findByUserId(user.getId()).ifPresent(activationRepository::delete);

        String rawToken = generateRawToken();
        String tokenHash = sha256Hex(rawToken);

        LocalDateTime now = LocalDateTime.now();

        Activation a = new Activation();
        a.setUser(user);
        a.setCreationDate(now);               // ✅ obavezno (NOT NULL)
        a.setExpirationDate(now.plusHours(24));
        a.setTokenHash(tokenHash);
        activationRepository.save(a);

        // ✅ putanja se poklapa sa kontrolerom ispod (/api/activation/verify)
        String verifyUrl = "https://localhost:8443/api/activation/verify?token=" + rawToken;
        sendActivationEmail(user, verifyUrl);
    }

    public void deleteActivation(Activation a) { activationRepository.delete(a); }

    public void sendActivationEmail(User user, String verifyUrl)
            throws MessagingException, UnsupportedEncodingException {
        String subject = "Please verify your registration";
        String senderName = "Public key infrastructure";

        String mailContent = """
          <div style='text-align:center;font-family:Arial,sans-serif;'>
            <h1 style='color:#007BFF;'>VERIFY YOUR ACCOUNT</h1>
            <p>Dear %s %s,</p>
            <p>Please click the link below to verify your registration:</p>
            <p><span style='color:#800080;'>Link expires in 24 hours</span></p>
            <h3><a href="%s">VERIFY</a></h3>
            <p>Thank you,<br>PKI Team26</p>
          </div>
          """.formatted(user.getFirstName(), user.getLastName(), verifyUrl);

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);
        helper.setFrom("eventPlanner879@gmail.com", senderName);
        helper.setTo(user.getEmail());
        helper.setSubject(subject);
        helper.setText(mailContent, true);
        mailSender.send(message);
    }
}

