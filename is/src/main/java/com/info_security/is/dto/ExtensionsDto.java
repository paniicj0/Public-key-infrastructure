package com.info_security.is.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ExtensionsDto {
    public boolean basicConstraintsCA; // true za CA
    public Integer pathLen;            // null ako ne želiš
    public boolean keyCertSign;        // za CA
    public boolean cRLSign;            // za CA
    public boolean digitalSignature;
    public boolean keyEncipherment;
    public boolean dataEncipherment;
    public boolean keyAgreement;
    public List<String> extendedKeyUsage; // npr ["serverAuth","clientAuth","codeSigning"]
    public List<String> subjectAltNames;  // npr DNS:example.com, IP:1.2.3.4
}