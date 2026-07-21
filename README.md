# ThreatLedger

ThreatLedger is a decentralized, privacy-preserving threat intelligence sharing protocol. Security analysts and independent researchers can anonymously publish, verify, and automatically act upon verified indicators of compromise (IoCs), network intrusion signatures, and threat data without relying on a centralized authority.

The core objective is collective defense: the moment a threat actor attempts an attack on a single protected node, their infrastructure is programmatically neutralized across the entire distributed network within minutes.

## Core Features

- **Decentralized Validation & Consensus:** Peer nodes across the network evaluate incoming submissions, automatically elevating threat statuses to `VERIFIED` once a strict 70% affirmative voting threshold is met (default: 3 minimum votes).
- **Anti-Spam Proof of Work:** A lightweight SHA-256 hash puzzle (default 4 leading zero hex chars) prevents network spamming and malicious data flooding. Both the dashboard and `find_nonce.py` mine nonces client-side before submitting.
- **Automated Client Mitigation:** `Agent.py` polls `GET /api/threats?status=VERIFIED` every 10 seconds and (on Linux) injects UFW firewall drops + Snort IDS signature rules for each new verified indicator.
- **AI Solidity Auditor (`POST /api/audit`):** An agentic Solidity source auditor that scans submitted smart contracts, classifies findings by severity (LOW → CRITICAL), and optionally escalates CRITICAL findings into the live threat feed — fusing web3 security with the IoC pipeline.
- **ZK Reputation Protocol (`/api/reputation`):** Decentralized Zero-Knowledge reputation. Nodes build Merkle commitments over signed credentials and present Schnorr-style membership proofs — verifiable without ever revealing the underlying PII/secret material.
- **Gemini-backed SOC Chatbot (`/api/chat`):** An in-dashboard AI assistant grounded in ThreatLedger's own architecture, powered by Google's Gemini 1.5 Flash model. Falls back to a safe offline mode if `GEMINI_API_KEY` is unset.
- **Tunable Consensus & PoW:** All thresholds live in `Backend/src/main/resources/application.properties` — change difficulty, min votes, and verify/reject percentages without touching code.

## System Architecture

The project is built using a highly decoupled microservices architecture divided into three core tiers:

1. **Backend Infrastructure:** A **Java 17 / Spring Boot 3.3** server that implements the business logic, consensus engine, ZK cryptography, Solidity audit pipeline, Gemini chat proxy, and a relational **SQL database** (H2 in-memory by default; MySQL for production) to manage state.
2. **User Interface:** A responsive, dependency-free security analyst dashboard built using plain **HTML, CSS, and vanilla JavaScript** (with the browser Web Crypto API for PoW mining). Visualizes active threat vectors, network consensus metrics, hosts the PoW submission portal, and embeds the floating Threat AI assistant widget.
3. **Automation Layer:** A client-side background **Python** agent (`Agent.py`) that pulls live intelligence over REST APIs and translates it directly into host OS security rules (UFW + Snort). A companion `mine_nonce.py` script demonstrates the PoW brute-force loop.

| Module | Sponsor file | Stack |
|---|---|---|
| Backend | `Backend/ThreatledgerBackendApplication.java` | Spring Boot 3.3.2, Java 17, JPA/Hibernate |
| Frontend | `Frontend/threatledger-dashboard.html` | Vanilla HTML/CSS/JS + Web Crypto API |
| Automation | `automation/Agent.py` | Python 3 + `requests` |
| DB schema reference | `database/schema.sql` | DDL fallback (entities auto-generate tables) |
| MySQL bootstrap | `automation/setup-mysql.ps1` | PowerShell (run as Administrator) |

## Getting Started

### Prerequisites — what to download and install

Each tier runs on a different stack. Install only what you need for the parts you plan to run.

#### 1. Backend (Java / Spring Boot)
- **JDK 17 or higher** — https://adoptium.net/ (Temurin recommended). Verify with `java -version`.
- **Maven** — https://maven.apache.org/download.cgi. Adds the `mvn` command to your terminal.
  - *Alternative:* install the VS Code **Extension Pack for Java** — it bundles Maven so you don't need a separate install.
- **MySQL Server** (optional) — https://dev.mysql.com/downloads/mysql/. Needed for production-style persistent storage.
  - You can skip this entirely and use the bundled **H2 in-memory database** (already configured by default in `Backend/src/main/resources/application.properties`). Zero setup, but data resets every restart — great for the hackathon demo.
  - On Windows, `automation/setup-mysql.ps1` installs the `MySQL84` service, sets the root password to `root`, creates the `threatledger` database, and flips `application.properties` over to MySQL automatically. Run it from an elevated PowerShell.
- **`GEMINI_API_KEY`** (optional) — environment variable consumed by `ChatController`. If absent the chatbot degrades to a fixed offline canned response.

#### 2. Automation layer (Python)
- **Python 3.8+** — https://www.python.org/downloads/. Verify with `python --version`.
- On Linux hosts where the agent actually blocks traffic: **UFW** (`sudo apt install ufw`) and **Snort IDS** (https://www.snort.org/downloads). Not needed on Windows dev machines — you can still run the agent and watch it poll the API (firewall calls will fail, which is expected).

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

Tables (`nodes`, `threats`, `votes`, `audit_reports`, `audit_findings`, `reputation_profiles`, `zk_credentials`, `zk_proof_records`) are auto-generated from the JPA `@Entity` classes on first run — you don't need to run `database/schema.sql` manually. That file is just a reference / manual fallback.

### Installation & Deployment — commands to run the project

Open a terminal per tier. Run them in this order so the API is up before the agent polls it.

#### Step 1 — Launch the backend API (port 8080)
```bash
cd Backend
mvn spring-boot:run
```
Server comes up at `http://localhost:8080`. H2 console (if you want to inspect data) is at `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:mem:threatledger`, user `sa`, no password).

*(Optional)* Set the Gemini API key for the chatbot before launching:
```bash
set GEMINI_API_KEY=your_key_here        # Windows cmd
$env:GEMINI_API_KEY="your_key_here"    # PowerShell
export GEMINI_API_KEY=your_key_here     # Linux / macOS
```

#### Step 2 — Start the web dashboard
Just open `Frontend/threatledger-dashboard.html` in your browser.
Or serve it over HTTP with Live Server / a static server:
```bash
cd Frontend
npx serve .
```
The dashboard fetches threats from `http://localhost:8080/api/threats` (CORS is open in dev) and the AI assistant widget posts to `http://localhost:8080/api/chat`.

#### Step 3 — Generate a proof-of-work nonce (required before submitting a threat)
The backend rejects any threat whose nonce doesn't satisfy the SHA-256 puzzle. Compute one before POSTing a new threat:
```bash
python Backend/scripts/find_nonce.py "198.51.100.42" 4
# or, from the automation folder:
python automation/mine_nonce.py "198.51.100.42" 4
```
(`4` = leading zero hex chars, matching `threatledger.pow.difficulty=4`. The dashboard mines this nonce in-browser via Web Crypto before each submit, so this script is only needed for programmatic/REST Client submissions.)

#### Step 4 — Deploy the security/automation agent
```bash
cd automation
pip install -r requirements.txt
python Agent.py
```
The agent polls `GET /api/threats?status=VERIFIED` every 10 seconds and (on Linux) injects UFW firewall drops + Snort rules for each new verified IP. On Windows it will still run and print its polling status, but the firewall calls will fail — that's expected.

### Quick API reference

#### Threat feed (`/api/threats`)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/threats` | Submit a new threat (needs valid PoW nonce) |
| `GET` | `/api/threats` | Live feed; filter with `?status=VERIFIED` \| `PENDING` \| `REJECTED` |
| `GET` | `/api/threats/{indicatorId}` | Fetch a single threat |
| `POST` | `/api/threats/{indicatorId}/vote` | Peer node casts a vote (`{ "votingNode": "...", "voteValue": true }`) |

#### AI Solidity auditor (`/api/audit`)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/audit` | Run the agentic audit loop on a Solidity source (`{ contractName, soliditySource, compilerVersion, submittedByNode, escalateToThreatFeed }`) |
| `GET` | `/api/audit` | List recent audit reports |
| `GET` | `/api/audit/{reportId}` | Fetch a specific audit report |

CRITICAL findings can be auto-escalated into the live threat feed by setting `escalateToThreatFeed=true` on the request.

#### ZK reputation protocol (`/api/reputation`)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/reputation/profiles` | Create a reputation profile (commits to secret identity material) |
| `GET` | `/api/reputation/profiles` | List all profiles |
| `GET` | `/api/reputation/profiles/{profileId}` | Fetch a profile |
| `POST` | `/api/reputation/profiles/{profileId}/credentials` | Issue a ZK credential to a profile |
| `POST` | `/api/reputation/profiles/{profileId}/proofs` | Generate a ZK identity proof |
| `POST` | `/api/reputation/proofs/verify` | Verify a ZK identity proof |
| `GET` | `/api/reputation/proofs` | List all proof records (no PII ever stored) |
| `POST` | `/api/reputation/profiles/{profileId}/membership` | Build a Merkle membership proof for a claim |
| `POST` | `/api/reputation/membership/verify` | Verify a membership proof |

#### AI SOC assistant (`/api/chat`)

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/chat` | Ask the ThreatLedger AI assistant a question (`{ "message": "..." }`); returns `{ "reply": "..." }`. Grounded in platform architecture via a system prompt; falls back to offline mode without `GEMINI_API_KEY`. |

### Tuning knobs (in `application.properties`)
- `threatledger.pow.difficulty` — leading zero hex chars required for the PoW hash (default `4`).
- `threatledger.consensus.min-votes` — votes required before a threat can be verified/rejected (default `3`).
- `threatledger.consensus.verify-threshold` — % of `true` votes to flip status to `VERIFIED` (default `70.0`).
- `threatledger.consensus.reject-threshold` — % of `false` votes to flip status to `REJECTED` (default `30.0`).

### Repository layout

```
ThreatLedger-NEXT-GEN-AI-hackathon-main/
+- Backend/                       Spring Boot API (threats + audit + reputation + chat)
|  +- src/main/java/com/threatledger/backend/
|  |  +- controller/               ThreatController, AuditController, ReputationController, ChatController
|  |  +- entity/                   JPA entities (Threat, Node, Vote, AuditReport, ZkCredential, ...)
|  |  +- service/                  ConsensusService, ProofOfWorkService, SolidityAuditorService,
|  |  |                            ZkReputationService, ZkCryptoService, ThreatService
|  |  +- dto/, repository/, exception/, config/
|  +- src/main/resources/application.properties
|  +- scripts/                     api-tests.http, find_nonce.py
+- Frontend/                       threatledger-dashboard.html (single-file dashboard + AI chat widget)
+- automation/                     Agent.py, mine_nonce.py, setup-mysql.ps1, requirements.txt
+- database/                       schema.sql (reference DDL)
+- README.md                       this file
```
