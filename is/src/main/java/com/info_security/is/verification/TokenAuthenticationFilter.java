package com.info_security.is.verification;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private TokenVerify tokenVerify;

    private UserDetailsService userDetailsService;


    public TokenAuthenticationFilter(TokenVerify tokenHelper, UserDetailsService userDetailsService) {
        this.tokenVerify = tokenHelper;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader("Authorization");
        System.out.println("------------------------ima token");
        if(token != null){
            if(token.startsWith("Bearer ")){
                token = token.substring(7);
            }
        }
        System.out.println("--------------------Token je:" + token);

        String username = tokenVerify.getUsernameFromToken(token);
        System.out.println("--------------------username:" + username);

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
            if (tokenVerify.validateToken(token, userDetails)) {
                System.out.println("--------------------Token verified:" );
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );

                auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                SecurityContextHolder.getContext().setAuthentication(auth);
                System.out.println("--------------------security context set:" + auth.toString());
            }
        }
        filterChain.doFilter(request, response);
    }

}

