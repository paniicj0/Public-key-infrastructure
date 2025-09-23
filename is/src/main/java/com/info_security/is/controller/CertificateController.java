package com.info_security.is.controller;

import com.info_security.is.dto.CertificateResponse;
import com.info_security.is.dto.EeRequest;
import com.info_security.is.dto.RevokeRequest;
import com.info_security.is.dto.RootRequest;
import com.info_security.is.model.Certificate;
import com.info_security.is.service.PkiService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/certs")
@RequiredArgsConstructor
public class CertificateController {

    private final PkiService pkiService;

    @PostMapping("/root")
    public ResponseEntity<CertificateResponse> createRoot(@Valid @RequestBody RootRequest req) throws Exception {
        Certificate saved = pkiService.generateRoot(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }

    @PostMapping("/ee")
    public ResponseEntity<CertificateResponse> issueEE(@Valid @RequestBody EeRequest req) throws Exception {
        Certificate saved = pkiService.issueEndEntity(req);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<byte[]> downloadPkcs12(@PathVariable Long id,
                                                 @RequestParam(defaultValue = "changeit") String password) throws Exception {
        // promena: lozinka kao query param
        byte[] pkcs12 = pkiService.generatePkcs12(id, password);
        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("application/x-pkcs12"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"cert.p12\"")
                .body(pkcs12);
    }

    @PatchMapping("/{id}/revoke")
    public ResponseEntity<CertificateResponse> revoke(@PathVariable Long id,
                                                      @Valid @RequestBody RevokeRequest req
    ) {

        Certificate saved = pkiService.revoke(id, req.getReason(), null);
        return ResponseEntity.ok(new CertificateResponse(saved));
    }
}
