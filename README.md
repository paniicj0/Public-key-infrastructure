Public Key Infrastructure (PKI) System

A comprehensive Public Key Infrastructure (PKI) system for centralized certificate management with multi-level hierarchy support.

🌟 Features
Certificate Hierarchy Management

Root CA certificates

Intermediate CA certificates

End-Entity certificates

Unlimited intermediate levels

Certificate Operations

Certificate generation with custom parameters

X.500 name support for certificate subjects

Certificate extensions management (keyCertSign, BasicConstraints, etc.)

Validity period configuration

Security Features

Digital signature validation

Certificate revocation status checking

Issuer certificate validity verification

User Management

Role-based access control (Admin, User)

Organization-based user segregation

Email activation system

JWT authentication

🏗️ System Architecture
Backend (Spring Boot)
Java 17+ with Spring Boot 3.0+

Spring Security with JWT authentication

Spring Data JPA for database operations

PostgreSQL database

Bouncy Castle for cryptographic operations

Frontend (Angular)
Angular 15+ with TypeScript

Angular Material for UI components

JWT authentication integration
