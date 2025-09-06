# 🔐 Public Key Infrastructure (PKI) System

A robust **Public Key Infrastructure (PKI)** application for centralized certificate management with a multi-level hierarchy (Root CA → Intermediate CA → End-Entity).  
Built with **Spring Boot** (backend) and **Angular** (frontend).

---

## ✨ Features

- **Certificate Hierarchy**
  - Root CA, unlimited Intermediate CAs, and End-Entity certificates
  - Extensions (BasicConstraints, KeyUsage, ExtendedKeyUsage, etc.)
- **Certificate Operations**
  - Generation (RSA/ECDSA), CSR handling, export (PEM/DER/PFX)
  - Revocation with CRL support and status validation
- **Security**
  - Digital signature creation and verification
  - Certificate chain trust validation
  - Planned CRL/OCSP support
- **User Management**
  - Role-based access (Admin, User)
  - Organization-based user separation
  - JWT authentication and email activation
- **Audit Logging**
  - Issuance/revocation logs with metadata for traceability

---

## 🧱 Architecture

- **Backend (Spring Boot)**
  - Spring Security + JWT
  - PostgreSQL via JPA/Hibernate
  - Java Cryptography (with BouncyCastle)
  - Email notifications for account activation

- **Frontend (Angular)**
  - Admin panel for CA management
  - User portal for certificate requests/downloads
  - Guards & interceptors for secure routing

---


