# ThreatLedger Backend (Member 1: Backend & Data Architect)

Spring Boot + SQL implementation of the backend layer described in your project doc:
schema for nodes/threats/votes, the REST API, the proof-of-work anti-spam check, and
the consensus engine.

## 1. Prerequisites

- Java 17+ (`java -version`)
- Maven (VS Code's Java Extension Pack bundles this, or install separately)
- MySQL Server running locally (or skip this and use the H2 option in `application.properties`)
- VS Code extensions: **Extension Pack for Java**, **Spring Boot Extension Pack**, and
  **REST Client** (for the `scripts/api-tests.http` file)

## 2. Set up the database

```sql
CREATE DATABASE threatledger;
```

Then open `src/main/resources/application.properties` and put your real MySQL
username/password in `spring.datasource.username` / `spring.datasource.password`.

Don't have MySQL installed and just want to get moving? Comment out the 4 MySQL lines
in that file and uncomment the H2 block instead — zero setup, but data resets every
time you restart the app (fine for early dev, not for your final demo).

You don't need to write any CREATE TABLE statements by hand — `spring.jpa.hibernate.ddl-auto=update`
generates the `nodes`, `threats`, and `votes` tables automatically from the `@Entity` classes
the first time you run the app.

## 3. Run it

In VS Code: open this folder, then run/debug `ThreatledgerBackendApplication.java`
(the play button above `main`), or from a terminal:

```bash
mvn spring-boot:run
```

Server comes up on `http://localhost:8080`.

## 4. Try it out

Open `scripts/api-tests.http` in VS Code (needs the REST Client extension) and click
"Send Request" above each block. Before submitting a threat, generate a valid nonce:

```bash
python scripts/find_nonce.py "198.51.100.42" 4
```

Paste the printed nonce into the `proofOfWorkNonce` field of the submission request.

## 5. What's implemented, mapped to your doc's "Key Tasks" for Member 1

| Doc task | Where it lives |
|---|---|
| SQL schema for nodes, threats, votes | `entity/Node.java`, `entity/Threat.java`, `entity/Vote.java` |
| Spring Boot REST API | `controller/ThreatController.java` |
| Proof-of-work (SHA-256 puzzle) | `service/ProofOfWorkService.java` |
| Consensus calculation (>70% -> VERIFIED) | `service/ConsensusService.java` |

## 6. API reference (matches the shared JSON contract)

### `POST /api/threats` — submit a new threat
Request body (exact contract shape):
```json
{
  "indicatorValue": "198.51.100.42",
  "indicatorType": "IP",
  "threatDescription": "Brute force attempts detected on SSH port 22.",
  "submittedByNode": "NODE-NODE-772A",
  "proofOfWorkNonce": 48291
}
```
Returns `201 Created` with the stored threat (status `PENDING`), or `400` if the
nonce doesn't satisfy the proof-of-work rule.

### `GET /api/threats` — the live feed
Optional query param `?status=VERIFIED` (or `PENDING` / `REJECTED`) — this is what
Member 3's Python script should call, filtering for `VERIFIED` only. Returns an array
in the exact contract shape:
```json
[
  {
    "indicatorId": 1024,
    "indicatorValue": "198.51.100.42",
    "indicatorType": "IP",
    "threatDescription": "Brute force attempts detected on SSH port 22.",
    "submittedByNode": "NODE-NODE-772A",
    "consensusStatus": "VERIFIED",
    "confidenceScore": 88.5,
    "totalVotesCast": 42,
    "createdAt": "2026-07-18T20:15:00Z"
  }
]
```

### `GET /api/threats/{indicatorId}` — a single threat

### `POST /api/threats/{indicatorId}/vote` — peer node casts a vote
**Heads-up:** this endpoint isn't in the original data contract doc — the doc describes
peer voting happening but never gave it a JSON shape, so I designed one. Share this with
Ruqayyah and your other teammate so everyone's on the same page:
```json
{
  "votingNode": "NODE-BETA-001",
  "voteValue": true
}
```
`voteValue: true` = "I also see this as malicious", `false` = "looks like a false positive".
A node can only vote once per threat (second attempt returns `400`). Returns the updated
threat with recalculated `confidenceScore` / `totalVotesCast` / `consensusStatus`.

## 7. Assumptions I made that aren't in the doc — flag these to your team

1. **Minimum vote count before flipping status.** The doc says ">70% verification
   threshold" but doesn't say how many votes are needed before that percentage counts.
   I added `threatledger.consensus.min-votes=3` (in `application.properties`) so a
   single vote can't instantly verify or reject a threat. Change the number there if
   your team wants a different minimum.
2. **The vote endpoint's shape** (see above) — needed for the consensus engine to have
   any data to work with, but wasn't in the shared contract.
3. **Proof-of-work difficulty** — set to 4 leading zero hex characters
   (`threatledger.pow.difficulty=4`), which takes a fraction of a second to a couple
   seconds to brute-force. Tune this in `application.properties` if it's too
   slow/fast during your demo.

## 8. For Member 3 (Python agent)

Polling loop should hit `GET /api/threats?status=VERIFIED` every X seconds, then take
each `indicatorValue` and pass it into the firewall-blocking command. Use
`scripts/find_nonce.py`'s logic as reference for how the PoW nonce needs to be computed
before any of your test submissions will be accepted.

## 9. For Member 2 (frontend)

Point your `fetch()` calls at `http://localhost:8080/api/threats`. CORS is wide open in
`config/CorsConfig.java` for dev, so any localhost port works out of the box.
