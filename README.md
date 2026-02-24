<div align="center">

<h1>🔐 Public Key Infrastructure (PKI) System</h1>

<p>
  A robust, enterprise-grade <strong>Public Key Infrastructure</strong> platform for centralized certificate lifecycle management,<br/>
  featuring a multi-level CA hierarchy, role-based access control, and cryptographic operations.
</p>

<!-- Badges -->
<p>
  <img src="https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=java&logoColor=white" alt="Java 17"/>
  <img src="https://img.shields.io/badge/Spring%20Boot-3.5.5-brightgreen?style=for-the-badge&logo=spring-boot&logoColor=white" alt="Spring Boot"/>
  <img src="https://img.shields.io/badge/PostgreSQL-16-blue?style=for-the-badge&logo=postgresql&logoColor=white" alt="PostgreSQL"/>
  <img src="https://img.shields.io/badge/Angular-Frontend-red?style=for-the-badge&logo=angular&logoColor=white" alt="Angular"/>
  <img src="https://img.shields.io/badge/BouncyCastle-1.78.1-lightgrey?style=for-the-badge&logo=letsencrypt&logoColor=white" alt="BouncyCastle"/>
  <img src="https://img.shields.io/badge/JWT-Auth-purple?style=for-the-badge&logo=jsonwebtokens&logoColor=white" alt="JWT"/>
  <img src="https://img.shields.io/badge/Maven-Build-C71A36?style=for-the-badge&logo=apache-maven&logoColor=white" alt="Maven"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License"/>
</p>

</div>

---

## 📖 Table of Contents

- [✨ Features](#-features)
- [🛠️ Technologies](#%EF%B8%8F-technologies)
- [🧱 Architecture](#-architecture)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
- [📁 Project Structure](#-project-structure)
- [🔑 API Overview](#-api-overview)
- [🔒 Security](#-security)
- [📜 License](#-license)

---

## ✨ Features

<table>
  <tr>
    <td>🏛️ <strong>Certificate Hierarchy</strong></td>
    <td>Root CA → unlimited Intermediate CAs → End-Entity certificates with full X.509 extension support</td>
  </tr>
  <tr>
    <td>📄 <strong>Certificate Operations</strong></td>
    <td>Key generation (RSA / ECDSA), CSR processing, export in PEM · DER · PFX formats</td>
  </tr>
  <tr>
    <td>🚫 <strong>Revocation</strong></td>
    <td>Certificate revocation with CRL generation and chain-level status validation</td>
  </tr>
  <tr>
    <td>👤 <strong>User Management</strong></td>
    <td>Role-based access (Admin / User), organization-scoped isolation, email account activation</td>
  </tr>
  <tr>
    <td>🔐 <strong>Cryptography</strong></td>
    <td>Digital signature creation & verification, encrypted keystores, master-key-protected private keys</td>
  </tr>
  <tr>
    <td>📋 <strong>Certificate Templates</strong></td>
    <td>Reusable templates with configurable KeyUsage, ExtendedKeyUsage, and validity periods</td>
  </tr>
  <tr>
    <td>📝 <strong>Audit Logging</strong></td>
    <td>Issuance / revocation logs with full metadata for traceability and compliance</td>
  </tr>
</table>

---

## 🛠️ Technologies

### Backend
| Technology | Version | Purpose |
|---|---|---|
| ☕ **Java** | 17 | Core language |
| 🍃 **Spring Boot** | 3.5.5 | Application framework |
| 🔒 **Spring Security** | (managed) | Authentication & authorization |
| 🗄️ **Spring Data JPA / Hibernate** | (managed) | ORM & database access |
| 🐘 **PostgreSQL** | 16+ | Relational database |
| 🔑 **BouncyCastle** | 1.78.1 | X.509 / PKI cryptography |
| 🎟️ **JJWT** | 0.11.5 | JSON Web Token handling |
| 📧 **Jakarta Mail** | 2.0.1 | Email notifications |
| 🏷️ **Lombok** | (managed) | Boilerplate reduction |
| 🔨 **Maven** | 3+ | Build & dependency management |

### Frontend
| Technology | Purpose |
|---|---|
| 🅰️ **Angular** | SPA framework for admin panel & user portal |
| 💅 **TypeScript** | Type-safe frontend development |
| 🛡️ **Route Guards & Interceptors** | Secure navigation & HTTP token injection |

---

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Angular Frontend                       │
│   ┌──────────────────┐        ┌──────────────────────────┐  │
│   │   Admin Panel    │        │      User Portal          │  │
│   │  (CA management) │        │  (cert requests/download) │  │
│   └────────┬─────────┘        └──────────┬────────────────┘  │
└────────────┼──────────────────────────────┼───────────────────┘
             │  HTTPS + JWT                 │
┌────────────▼──────────────────────────────▼───────────────────┐
│                     Spring Boot Backend (port 8443)            │
│  ┌──────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Auth API   │  │  Certificate API │  │  Template API   │  │
│  └──────┬───────┘  └────────┬────────┘  └────────┬────────┘  │
│         │                   │                     │           │
│  ┌──────▼───────────────────▼─────────────────────▼────────┐  │
│  │              Spring Security + JWT Filter                 │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                             │                                  │
│  ┌──────────────────────────▼───────────────────────────────┐  │
│  │           Service Layer (PKI / Crypto / User)             │  │
│  └──────┬──────────────────────────────────────┬────────────┘  │
│         │  BouncyCastle (X.509, PKCS#12, CRL)  │ JPA/Hibernate │
│  ┌──────▼─────────────┐              ┌──────────▼────────────┐  │
│  │  Encrypted         │              │      PostgreSQL        │  │
│  │  File Keystores    │              │        Database        │  │
│  └────────────────────┘              └───────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

### CA Hierarchy
```
Root CA (self-signed)
  └── Intermediate CA 1
        ├── Intermediate CA 2
        │     └── End-Entity Certificate
        └── End-Entity Certificate
```

---

## 🚀 Getting Started

### Prerequisites

- **Java 17+** — [Download](https://adoptium.net/)
- **Maven 3.8+** — [Download](https://maven.apache.org/download.cgi)
- **PostgreSQL 16+** — [Download](https://www.postgresql.org/download/)
- *(Optional)* **Node.js 18+ & Angular CLI** for the frontend

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/paniicj0/Public-key-infrastructure.git
   cd Public-key-infrastructure/is
   ```

2. **Create the database**
   ```sql
   CREATE DATABASE pki_db;
   ```

3. **Configure `application.properties`**
   ```properties
   spring.datasource.url=jdbc:postgresql://localhost:5432/pki_db
   spring.datasource.username=<your_pg_user>
   spring.datasource.password=<your_pg_password>

   pki.keystore.dir=<absolute_path_to_keystore_directory>
   pki.keystore.password=<your_keystore_password>

   app.jwt.secret.base64=<base64_encoded_256bit_secret>
   app.crypto.masterKeyB64=<base64_encoded_256bit_master_key>
   ```

4. **Build and run**
   ```bash
   ./mvnw spring-boot:run
   ```
   The API will be available at `https://localhost:8443`

---

## 📁 Project Structure

```
is/
├── src/main/java/com/info_security/is/
│   ├── config/           # Crypto & application configuration
│   ├── controller/       # REST API endpoints
│   │   ├── AuthController
│   │   ├── CertificateController
│   │   ├── CertificateIssueController
│   │   ├── CertificateTemplateController
│   │   └── UserController
│   ├── crypto/           # PKI cryptographic utilities
│   │   ├── CryptoUtil    # Key generation, signing, verification
│   │   ├── CsrUtil       # CSR creation and processing
│   │   ├── Keystores     # PKCS#12 keystore management
│   │   ├── MasterKeyProvider
│   │   └── PemUtil       # PEM encoding/decoding
│   ├── dto/              # Data Transfer Objects
│   ├── enums/            # Certificate types, key usages, roles
│   ├── model/            # JPA entities (CA, Certificate, User, …)
│   ├── repository/       # Spring Data JPA repositories
│   ├── service/          # Business logic
│   └── verification/     # JWT filter, CORS, security config
└── src/main/resources/
    ├── application.properties
    ├── keystore.p12       # Server TLS keystore
    └── server.p12
```

---

## 🔑 API Overview

| Method | Endpoint | Description | Role |
|--------|----------|-------------|------|
| `POST` | `/auth/login` | Authenticate and receive JWT | Public |
| `POST` | `/auth/register` | Register a new user | Public |
| `GET` | `/auth/activate/{token}` | Activate account via email | Public |
| `GET` | `/certificates` | List certificates | User / Admin |
| `POST` | `/certificates/issue` | Issue a new certificate | Admin |
| `POST` | `/certificates/revoke` | Revoke a certificate | Admin |
| `GET` | `/certificates/{id}/download` | Download certificate (PEM/DER/PFX) | User / Admin |
| `GET` | `/templates` | List certificate templates | Admin |
| `POST` | `/templates` | Create a certificate template | Admin |
| `GET` | `/users` | List users | Admin |

---

## 🔒 Security

- All communication is over **HTTPS (TLS)** — port `8443`
- Passwords and private keys are **never stored in plaintext** — PKCS#12 keystores with master-key encryption
- **JWT** (HS512) with configurable access (15 min) and refresh (14 day) token expiry
- **Role-based authorization** enforced at the controller level via Spring Security
- **Email verification** required before account activation

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  <sub>Built with ❤️ using Spring Boot, BouncyCastle, and Angular</sub>
</div>
