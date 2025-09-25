package com.info_security.is.config;

import com.info_security.is.crypto.CryptoUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoConfig {
    @Bean
    public CryptoUtil cryptoUtil() {
        String b64 = System.getenv("MASTER_KEY_B64");
        if (b64 == null) {
            // DEV fallback za lakši start (32 bajta 'a' → base64)
            b64 = "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=";
        }
        return new CryptoUtil(b64);
    }
}
