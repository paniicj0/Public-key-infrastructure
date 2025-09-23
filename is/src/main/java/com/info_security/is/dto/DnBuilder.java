package com.info_security.is.dto;
import java.util.ArrayList;
import java.util.List;

public final class DnBuilder {
    private DnBuilder() {}

    public static String toDn(SubjectDto s) {
        List<String> parts = new ArrayList<>();
        if (s.getCn() != null && !s.getCn().isBlank()) parts.add("CN=" + s.getCn());
        if (s.getOu() != null && !s.getOu().isBlank()) parts.add("OU=" + s.getOu());
        if (s.getO() != null  && !s.getO().isBlank())  parts.add("O="  + s.getO());
        if (s.getE() != null  && !s.getE().isBlank())  parts.add("E="  + s.getE());
        if (s.getC() != null  && !s.getC().isBlank())  parts.add("C="  + s.getC());
        return String.join(", ", parts);
    }
}
