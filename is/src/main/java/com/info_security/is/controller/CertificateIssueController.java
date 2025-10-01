package com.info_security.is.controller;

import com.info_security.is.dto.AutogenReq;
import com.info_security.is.dto.IssueResp;
import com.info_security.is.service.PkiService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api/certs")
@RequiredArgsConstructor
public class CertificateIssueController {

    private final PkiService pkiIssueService;

    @PostMapping(value = "/issue-from-csr", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyAuthority('ADMIN','CA','USER')")
    public ResponseEntity<?> issueFromCsr(
            @RequestPart("csr") MultipartFile csrFile,
            @RequestParam Long issuerId,
            @RequestParam Integer validityDays) {
        try {
            String csrPem = new String(csrFile.getBytes(), StandardCharsets.UTF_8);
            Long id = pkiIssueService.issueFromCsr(issuerId, validityDays, csrPem);
            return ResponseEntity.ok(new IssueResp(id));
        } catch (Exception e) {
            // vrati čitljivu poruku do fronta (400)
            return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
        }
    }


    // === Autogenerate ===
    @PostMapping(value = "/issue-autogen", produces = { MediaType.APPLICATION_JSON_VALUE, "application/x-pkcs12" })
    @PreAuthorize("hasAnyAuthority('USER','CA','ADMIN')")
    public ResponseEntity<?> issueAutogen(@RequestBody AutogenReq req) throws Exception {
        var r = pkiIssueService.issueAutogen(
                req.issuerId(), req.validityDays(), req.keySize(),
                req.subject(), Boolean.TRUE.equals(req.downloadP12()),
                req.p12Password()
        );
        if (Boolean.TRUE.equals(req.downloadP12())) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=keystore.p12")
                    .contentType(MediaType.parseMediaType("application/x-pkcs12"))
                    .body(r.p12Bytes());
        }
        return ResponseEntity.ok(new IssueResp(r.id()));
    }
}
