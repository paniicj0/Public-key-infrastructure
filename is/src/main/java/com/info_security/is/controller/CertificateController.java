package com.info_security.is.controller;

import com.info_security.is.dto.*;
import com.info_security.is.model.CertificateModel;
import com.info_security.is.repository.CertificateRepository;
import com.info_security.is.service.PkiService;
import com.info_security.is.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/certs")
@RequiredArgsConstructor
public class CertificateController {

    private final PkiService pkiService;
    private final CertificateRepository repo;
    private final UserService userService;




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

    @PostMapping("/caUser-create-ca")
    public ResponseEntity<CertificateResponse> issueCAcreateByCaUser(@Valid @RequestBody CaRequest req) throws Exception {
        CertificateModel saved = pkiService.issueIntermediateCaUser(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }

    @PostMapping("/ee")
    public ResponseEntity<CertificateResponse> issueEE(@Valid @RequestBody EeRequest req) throws Exception {
        CertificateModel saved = pkiService.issueEndEntity(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }

    //KREIRA GA CA USER EE TEST
    @PostMapping("/caUser-create-ee")
    public ResponseEntity<CertificateResponse> issueEEcreateByCaUser(@Valid @RequestBody EeRequest req) throws Exception {
        CertificateModel saved = pkiService.issueEndEntitycreateCAuser(req);
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

  
    @GetMapping("/{id}")
    public ResponseEntity<CertificateResponse> getById(@PathVariable Long id) {
        return repo.findById(id)
                .map(c -> ResponseEntity.ok(new CertificateResponse(c)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    // --------------------------- GET -----------------------------------
    @GetMapping("/getAll")
    public List<CertificateResponse> listAll() {
        return pkiService.listCertificates();
    }


    // CA sertifikati
    @GetMapping("/ca-certs")
    public List<CertificateResponse> listCACertificates() {
        return pkiService.listCertificatesCA();
    }


    // --------------------- POVLACENJE -------------------------
    @PostMapping("/{id}/revoke")
    public ResponseEntity<RevokeResponse> revoke(@PathVariable Long id, @RequestBody RevokeRequest req) {
        CertificateModel saved = pkiService.revoke(id, req != null ? req.getReason() : null);
        return ResponseEntity.ok(
                new RevokeResponse(saved.getId(), saved.isRevoked(), saved.getRevocationReason(),
                        saved.getRevokedAt() != null ? saved.getRevokedAt().toString() : null)
        );
    }
}



