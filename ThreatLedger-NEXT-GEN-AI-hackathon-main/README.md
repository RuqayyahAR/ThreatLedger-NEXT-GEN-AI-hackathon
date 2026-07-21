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
### Prerequisites — what to download and install

- Java Development Kit (JDK 17 or higher)
- Python 3.x
- Node.js (if running advanced UI dependencies) or a basic local web server
- Relational Database (MySQL / PostgreSQL / SQLite)
Each tier of the project runs on a different stack. Install only what you need for the parts you plan to run.

### Installation & Deployment
#### 1. Backend (Java / Spring Boot)
- **JDK 17 or higher** — https://adoptium.net/ (Temurin recommended). Verify with `java -version`.
- **Maven** — https://maven.apache.org/download.cgi. Adds the `mvn` command to your terminal.
  - *Alternative:* install the VS Code **Extension Pack for Java** — it bundles Maven so you don't need a separate install.
- **MySQL Server** (optional) — https://dev.mysql.com/downloads/mysql/. Needed for production-style persistent storage.
  - You can skip this entirely and use the bundled **H2 in-memory database** (already configured by default in `Backend/src/main/resources/application.properties`). Zero setup, but data resets every restart — great for the hackathon demo.

1. **Database Setup:** Run the database schema generation scripts in your SQL instance.
2. **Launch Backend API:** Navigate to the Java core directory and boot the Spring Boot application profile.
3. **Start the Web Dashboard:** Open the dashboard interface via your local runtime hosting environment.
4. **Deploy the Security Agent:** Run the client-side automation engine using Python:
   ```bash
   sudo python agent.py
#### 2. Automation layer (Python)
- **Python 3.x** — https://www.python.org/downloads/. Verify with `python --version`.
- On Linux hosts where the agent actually blocks traffic: **UFW** (`sudo apt install ufw`) and **Snort IDS** (https://www.snort.org/downloads). Not needed on Windows dev machines — you can still run the agent and watch it poll the API.

#### 3. Frontend (dashboard)
- Any modern browser. The dashboard is plain **HTML, CSS, and JavaScript** — no build step.
- *(Optional)* **Node.js** + a static server (e.g. `npx serve`) or the VS Code **Live Server** extension, if you want to serve the page over HTTP instead of opening the file directly.

#### VS Code extensions (recommended)
- **Extension Pack for Java** — Java language + Maven support.
- **Spring Boot Extension Pack** — run/debug the backend from the editor.
- **REST Client** — lets you fire the requests in `Backend/scripts/api-tests.http` with one click.

### Database setup

The default config uses **H2 in-memory** out of the box, so you can skip this step for the demo.

If you want MySQL instead:
```sql
CREATE DATABASE threatledger;
```
Then open `Backend/src/main/resources/application.properties` and:
1. Comment out the 4 H2 lines (Option B block).
2. Uncomment the 4 MySQL lines (Option A block) and set your real `username` and `password`.

Tables (`nodes`, `threats`, `votes`) are auto-generated from the JPA `@Entity` classes on first run — you don't need to run `database/schema.sql` manually. That file is just a reference / manual fallback.

### Installation & Deployment — commands to run the project

Open a terminal per tier. Run them in this order so the API is up before the agent polls it.

#### Step 1 — Launch the backend API (port 8080)
```bash
cd Backend
mvn spring-boot:run
```
Server comes up at `http://localhost:8080`. H2 console (if you want to inspect data) is at `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:mem:threatledger`, user `sa`, no password).

#### Step 2 — Start the web dashboard
Just open `Frontend/threatledger-dashboard.html` in your browser.
Or serve it over HTTP with Live Server / a static server:
```bash
cd Frontend
npx serve .
```
The dashboard fetches threats from `http://localhost:8080/api/threats` (CORS is open in dev).

#### Step 3 — Generate a proof-of-work nonce (required before submitting a threat)
The backend rejects any threat whose nonce doesn't satisfy the SHA-256 puzzle. Compute one before POSTing a new threat:
```bash
python Backend/scripts/find_nonce.py "198.51.100.42" 4
```
(`4` = leading zero hex chars, matching `threatledger.pow.difficulty=4`. Paste the printed nonce into the `proofOfWorkNonce` field of your submission request — easiest via `Backend/scripts/api-tests.http` and the REST Client extension.)

#### Step 4 — Deploy the security/automation agent
```bash
cd automation
pip install -r requirements.txt
python Agent.py
```
The agent polls `GET /api/threats?status=VERIFIED` every 10 seconds and (on Linux) injects UFW firewall drops + Snort rules for each new verified IP. On Windows it will still run and print its polling status, but the firewall calls will fail — that's expected.

### Quick API reference

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/threats` | Submit a new threat (needs valid PoW nonce) |
| `GET` | `/api/threats` | Live feed; filter with `?status=VERIFIED` \| `PENDING` \| `REJECTED` |
| `GET` | `/api/threats/{indicatorId}` | Fetch a single threat |
| `POST` | `/api/threats/{indicatorId}/vote` | Peer node casts a vote (`{ "votingNode": "...", "voteValue": true }`) |

### Tuning knobs (in `application.properties`)
- `threatledger.pow.difficulty` — leading zero hex chars required for the PoW hash (default `4`).
- `threatledger.consensus.min-votes` — votes required before a threat can be verified/rejected (default `3`).
- `threatledger.consensus.verify-threshold` — % of `true` votes to flip status to `VERIFIED` (default `70.0`).
- `threatledger.consensus.reject-threshold` — % of `false` votes to flip status to `REJECTED` (default `30.0`).
