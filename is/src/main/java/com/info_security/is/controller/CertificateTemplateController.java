package com.info_security.is.controller;

import com.info_security.is.dto.CreateTemplateRequest;
import com.info_security.is.dto.TemplateResponse;
import com.info_security.is.dto.UpdateTemplateRequest;
import com.info_security.is.model.User;
import com.info_security.is.service.CertificateTemplateService;
import com.info_security.is.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

@RestController
@RequestMapping("/api/templates")
@PreAuthorize("hasAnyAuthority('CA','ADMIN')") // ⬅ 1) stavljeno na nivo kontrolera
public class CertificateTemplateController {

    private final CertificateTemplateService service;
    private final UserService userService; // ⬅ 2) uvodimo UserService umesto @AuthenticationPrincipal

    public CertificateTemplateController(CertificateTemplateService service,
                                         UserService userService) {
        this.service = service;
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<TemplateResponse> create(@Valid @RequestBody CreateTemplateRequest req) {
        User me = requireCurrentUser(); // ⬅ 3) centralizovano dobijanje user-a
        TemplateResponse resp = service.create(req, me);
        // Napomena: ako TemplateResponse ima public polje id, radi resp.id; ako ima getter, koristi resp.getId()
        URI location = URI.create("/api/templates/" + (resp.id != null ? resp.id : resp.getId()));
        return ResponseEntity.created(location).body(resp);
    }

    @GetMapping
    public List<TemplateResponse> listMine() {
        User me = requireCurrentUser();
        return service.listMine(me);
    }

    @GetMapping("/{id}")
    public TemplateResponse get(@PathVariable Long id) {
        User me = requireCurrentUser();
        return service.getMine(id, me);
    }

    @PutMapping("/{id}")
    public TemplateResponse update(@PathVariable Long id,
                                   @Valid @RequestBody UpdateTemplateRequest req) {
        User me = requireCurrentUser();
        return service.update(id, req, me);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        User me = requireCurrentUser();
        service.delete(id, me);
        return ResponseEntity.noContent().build();
    }

    // --- helpers ---
    private User requireCurrentUser() {
        User me = userService.getCurrentUser();
        if (me == null) throw new SecurityException("User not authenticated");
        return me;
    }
}
