package com.info_security.is.controller;

import com.info_security.is.dto.*;
import com.info_security.is.model.CertificateModel;
import com.info_security.is.repository.CertificateRepository;
import com.info_security.is.service.PkiService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/certs")
@RequiredArgsConstructor
public class CertificateController {

    private final PkiService pkiService;
    private final CertificateRepository repo;


    // ----------------------- IZDAVANJE SERTIFIKATA ----------------------------------
    @PostMapping("/root")
    public ResponseEntity<CertificateResponse> createRoot(@Valid @RequestBody RootRequest req) throws Exception {
        CertificateModel saved = pkiService.generateRoot(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }
    @PostMapping("/ca")
    public ResponseEntity<CertificateResponse> issueCA(@Valid @RequestBody CaRequest req) throws Exception {
        CertificateModel saved = pkiService.issueIntermediate(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }

    @PostMapping("/ee")
    public ResponseEntity<CertificateResponse> issueEE(@Valid @RequestBody EeRequest req) throws Exception {
        CertificateModel saved = pkiService.issueEndEntity(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }


    // -------------------------- PREUZIMANJE SERTIFIKATA -------------------------------------------

    @GetMapping("/{id}/download/pem")
    public ResponseEntity<byte[]> downloadPem(@PathVariable Long id) {
        var e = repo.findById(id)
                .orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.NOT_FOUND, "Certificate not found"));

        byte[] bytes = e.getCertificatePem().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cert-" + id + ".pem\"")
                .contentType(org.springframework.http.MediaType.parseMediaType("application/x-pem-file"))
                .body(bytes);
    }

    @GetMapping("/{id}/download/p12")
    public ResponseEntity<byte[]> downloadP12(@PathVariable Long id,
                                              @RequestParam(defaultValue = "changeit") String password) throws Exception {

        repo.findById(id).orElseThrow(() -> new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.NOT_FOUND, "Certificate not found"));

        byte[] p12 = pkiService.generatePkcs12(id, password);
        return ResponseEntity.ok()
                .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cert-" + id + ".p12\"")
                .contentType(org.springframework.http.MediaType.parseMediaType("application/x-pkcs12"))
                .body(p12);
    }
}



