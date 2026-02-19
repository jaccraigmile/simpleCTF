# BankingAI Cloud — CTF Challenge

## The Story

BankingAI Cloud is a fast-growing fintech startup that markets itself as the future of AI-driven banking infrastructure. Behind the polished landing page, a whistleblower has tipped off your team that the company is quietly exfiltrating customer financial data and routing it through shell accounts.

Your job is to get inside their internal employee portal, escalate your access, and prove you were there. The company's security team is confident their platform is locked down. Prove them wrong.

**Get in. Get the flags. Get out.**

---

## Description

A multi-stage web challenge built around a PHP employee portal backed by MySQL. Players work through a chain of vulnerabilities across the application, each rewarding a flag. No CVEs, no guessing — just enumeration, exploitation, and escalation.

The final objective is to read `/flag.txt` from the server — you'll need to find a way to execute code to get there.

- **Difficulty:** Medium
- **Category:** Web
- **Flags:** 5

---

## Running the Challenge

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/) (included with Docker Desktop)

### Start

```bash
git clone <repo-url>
cd challenge
docker compose up --build -d
```

The challenge will be available at **http://localhost** once both containers are healthy. The database takes ~30 seconds to initialise on first run.

### Stop

```bash
docker compose down
```

### Reset (wipe DB and start fresh)

```bash
docker compose down -v
docker compose up --build -d
```

---

## Running Multiple Teams

Each team gets their own isolated instance on a separate port. Scripts are in `scripts/`.

**Add a team** (auto-assigns port from 8000 upward):
```bash
bash scripts/add_team.sh alpha
# or specify a port:
bash scripts/add_team.sh bravo 8001
```

**Remove a team** (stops containers and wipes DB volume):
```bash
bash scripts/remove_team.sh alpha
```

**List running teams:**
```bash
bash scripts/list_teams.sh
```

On first run the web image is built. Subsequent teams reuse the cached image and start in seconds.

---

## Customising Flags

All flags are set as environment variables in `docker-compose.yaml`. Edit the values under each service's `environment` block before building:

```yaml
web:
  environment:
    FLAG_LOGIN:        "CTF{your_flag}"
    FLAG_INSPECTED:    "CTF{your_flag}"
    FLAG_ADMIN_ACCESS: "CTF{your_flag}"
    FLAG_FILE_UPLOAD:  "CTF{your_flag}"

db:
  environment:
    FLAG_CREDENTIAL_HARVESTER: "CTF{your_flag}"
```

Then rebuild:

```bash
docker compose up --build -d
```

---

## Author

SWOCTS
