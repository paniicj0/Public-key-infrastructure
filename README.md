A comprehensive Public Key Infrastructure (PKI) system for centralized certificate management with a multi-level hierarchy.

🌟 Features
Certificate Hierarchy Management

Root CA certificates

Intermediate CA certificates

End-Entity certificates

Unlimited intermediate levels

Certificate Operations

Certificate generation with custom parameters

X.500 subject names

Extensions management (e.g., keyCertSign, BasicConstraints, …)

Configurable validity period

Security

Digital signature validation

Certificate revocation status checks

Issuer certificate validity verification

User & Org Management

Role-based access control (Admin, User)

Organization-scoped users

Email activation flow

JWT authentication

🏗️ System Architecture
Backend (Spring Boot)

Java 17+, Spring Boot 3.0+

Spring Security (JWT)

Spring Data JPA

PostgreSQL

Bouncy Castle (crypto)

Frontend (Angular)

Angular 15+ (TypeScript)

Angular Material (UI)

JWT integration

🧰 Tech Stack

Backend: Java, Spring Boot, Spring Security, JPA/Hibernate, Bouncy Castle

Database: PostgreSQL

Frontend: Angular, Angular Material

Auth: JWT

License: MIT

🚀 Getting Started (high-level)
# Backend
# 1) Configure PostgreSQL connection in application.yml/properties
# 2) Build & run
./mvnw spring-boot:run

# Frontend
# 1) Install deps
npm install
# 2) Run dev server
ng serve


Make sure Java 17+, Node.js (for Angular), and PostgreSQL 13+ are installed.

📄 License

This project is licensed under the MIT License.
