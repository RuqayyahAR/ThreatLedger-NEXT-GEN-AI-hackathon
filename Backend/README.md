# Threat Ledger - Backend Engine

The core API and processing engine for the Threat Ledger platform. This backend ingests, parses, and normalizes open-source threat intelligence (OSINT), stores indicator of compromise (IoC) data, and provides high-performance query endpoints for security analysts.

## Architecture & Core Tech

*   **Runtime/Framework:** Node.js with FastAPI / Express (adjust based on your actual framework)
*   **Database:** PostgreSQL (for relational logs/users) + Redis (for high-speed IoC caching)
*   **Data Models:** STIX 2.1 compliant schema for interoperability

---

## Getting Started

### Prerequisites
*   Docker and Docker Compose
*   Node.js v20+ / Python 3.11+
*   A valid API key for external feeds (e.g., AlienVault OTX, VirusTotal)

### Local Setup

1. **Clone the repository and enter the backend directory:**
   ```bash
   cd threat-ledger/backend
