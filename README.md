# Enterprise Mobile Authentication Lab

A production-style authentication demo platform built on RHEL 9 to simulate a mobile banking authentication workflow.

## Features
- Username/password login
- OTP verification
- Biometric approval simulation
- Voice approval simulation
- JWT token issuance
- Protected REST APIs
- Apache reverse proxy
- Tomcat integration
- systemd-managed backend service
- Failure testing for token expiration and downstream dependency outage

## Stack
- Python Flask
- Apache httpd
- Apache Tomcat
- SQLite
- JWT
- systemd
- RHEL 9

## Current Phase
Phase 1 complete:
- Core authentication flow working
- Apache proxy working
- Tomcat dependency working
- Failure scenarios demonstrated

## Next Phase
- GitHub Actions CI/CD
- deployment scripts
- smoke tests
- Terraform IaC
