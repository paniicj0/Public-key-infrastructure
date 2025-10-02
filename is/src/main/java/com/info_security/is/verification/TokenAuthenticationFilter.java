package com.info_security.is.verification;

import com.info_security.is.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private final TokenVerify tokens;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest req,
                                    HttpServletResponse res,
                                    FilterChain chain) throws ServletException, IOException {

        // 1) Uvek pokupi Authorization header
        String authz = req.getHeader(HttpHeaders.AUTHORIZATION);

        if (authz != null && authz.startsWith("Bearer ")) {
            String jwt = authz.substring(7);
            try {
                // 2) Priznaj samo ACCESS tokene
                if (tokens.isAccess(jwt)) {
                    String username = tokens.getUsername(jwt);
                    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        var ud = userService.loadUserByUsername(username);
                        var auth = new UsernamePasswordAuthenticationToken(
                                ud, null, ud.getAuthorities());
                        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        log.debug("[SEC] Auth OK for {}", username);
                    }
                } else {
                    log.debug("[SEC] JWT je REFRESH, preskačem");
                }
            } catch (Exception e) {
                // Ne ruši zahtev – samo loguj i pusti dalje (onda @PreAuthorize vrati 401/403)
                log.warn("[SEC] JWT nije validan: {}", e.getMessage());
            }
        } else {
            log.debug("[SEC] Authorization header nema ili ne počinje sa 'Bearer ' (path: {})", req.getRequestURI());
        }

        chain.doFilter(req, res);
    }
}
