# ThreatLedger-NEXT-GEN-AI-hackathon

# ThreatLedger

ThreatLedger is a decentralized, privacy-preserving threat intelligence sharing protocol. It allows security analysts and independent researchers to anonymously publish, verify, and automatically act upon verified indicators of compromise (IoCs), network intrusion signatures, and threat data without relying on a centralized authority.

The core objective is collective defense: the moment a threat actor attempts an attack on a single protected node, their infrastructure is programmatically neutralized across the entire distributed network within minutes.

## Core Features

- **Decentralized Validation & Consensus:** Peer nodes across the network evaluate incoming submissions, automatically elevating threat statuses to "Verified" once a designated voting threshold is met.
- **Anti-Spam Proof of Work:** A lightweight cryptographic hash puzzle verification prevents network spamming and malicious data flooding.
- **Automated Client Mitigation:** Client systems running the local automation daemon dynamically pull verified threat listings and update system firewalls and intrusion detection rules in real time.

## System Architecture

The project is built using a highly decoupled microservices architecture divided into three core tiers:

1. **Backend Infrastructure:** A **Java (Spring Boot)** server that implements the business logic, consensus calculations, API endpoints, and a relational **SQL database** to manage state data.
2. **User Interface:** A responsive security analyst dashboard built using **HTML, CSS, and JavaScript** that visualizes active threat vectors, network consensus metrics, and entry portals for new reports.
3. **Automation Layer:** A client-side background **Python** agent that pulls live intelligence over REST APIs and translates it directly into host OS security rules.

## Getting Started

### Prerequisites

- Java Development Kit (JDK 17 or higher)
- Python 3.x
- Node.js (if running advanced UI dependencies) or a basic local web server
- Relational Database (MySQL / PostgreSQL / SQLite)

### Installation & Deployment

1. **Database Setup:** Run the database schema generation scripts in your SQL instance.
2. **Launch Backend API:** Navigate to the Java core directory and boot the Spring Boot application profile.
3. **Start the Web Dashboard:** Open the dashboard interface via your local runtime hosting environment.
4. **Deploy the Security Agent:** Run the client-side automation engine using Python:
   ```bash
   sudo python agent.py
