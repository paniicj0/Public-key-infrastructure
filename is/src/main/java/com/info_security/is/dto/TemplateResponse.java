package com.info_security.is.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class TemplateResponse {
    public Long id;
    public String name;
    public Long issuerId;
    public String cnRegex;
    public String sanRegex;
    public Integer ttlDays;
    public List<String> keyUsage;
    public List<String> extendedKeyUsage;
    public Long ownerUserId;
    public LocalDateTime createdAt;
    public LocalDateTime updatedAt;
}
