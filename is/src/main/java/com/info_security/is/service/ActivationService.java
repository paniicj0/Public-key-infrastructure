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



@Service
public class ActivationService {

    @Autowired
    private ActivationRepository activationRepository;

    @Autowired
    private JavaMailSender mailSender;

    public Activation save(Activation activation) {
        return activationRepository.save(activation);
    }


    public Activation findOne(Long id){return activationRepository.findById(id).orElseGet(null);}

    public Activation getActivationByUserId(Long userId) {

        return activationRepository.findByUserId(userId)
                .orElseThrow(() -> new EntityNotFoundException("Activation not found for User with ID: " + userId));
    }

    public void deleteActivation(Activation a) {
        activationRepository.delete(a);
    }

    public void sendActivationEmail(User user) throws MessagingException, UnsupportedEncodingException, jakarta.mail.MessagingException {
        //slanje mejla

        String subject = "Please verify your registration";
        String senderName = "Public key infrastructure";

        String mailContent = "<div style='text-align: center; font-family: Arial, sans-serif;'>";
        mailContent += "<h1 style='color: #007BFF;'>VERIFY YOUR ACCOUNT</h1>";
        mailContent += "<p>Dear " + user.getFirstName() + " " + user.getLastName() + ",</p>";
        mailContent += "<p>Please click the link below to verify your registration:</p>";
        mailContent += "<p><span style='color: #800080;'>Link expires in 24 hours</span></p>";

        // u slanju maila
        mailContent += "<h3><a href=\"http://localhost:8080/api/activation/verify/"
                + user.getId() + "\">VERIFY</a></h3>";
        mailContent += "<p>Thank you,<br>PKI Team26</p>";
        mailContent += "</div>";

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom("eventPlanner879@gmail.com", senderName);
        helper.setTo(user.getEmail());
        helper.setSubject(subject);
        helper.setText(mailContent, true);

        mailSender.send(message);
    }

}
