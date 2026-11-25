# NetWatch

A network intrusion detection system with automatic response and a live dashboard.
Suricata rules catch known attack patterns, a flow classifier catches behaviour the rules miss, and a response engine blocks offenders through nftables. A Next.js dashboard shows it all as it happens.

- **Demo mode** runs anywhere with one command. A simulated sensor produces Suricata-style events, so there is nothing to capture.
- **Lab mode** runs real Suricata against a victim container, with an attacker container to fire at it.

## How it works

```
 traffic ──> Suricata ──> eve.json ──> API ─┬─> signature alerts ──┐
 (or the demo simulator)                    │                      ├─> response engine ──> nftables
                                            └─> flow classifier ───┘        │
                                                (per-source windows)        v
                                                                      SQLite + SSE ──> Next.js dashboard
```

| Part | What it does |
| --- | --- |
| `suricata/rules/local.rules` | Five custom rules: port scan, SSH brute force, SQL injection, DNS tunneling, SYN flood. Each maps to a MITRE ATT&CK technique. |
| `api/app/eve.py` | Parses EVE JSON and tails the log file, surviving rotation. |
| `api/app/ml.py` | Groups flows into per-source episodes and computes behaviour features over a 60 second window (flows per second, unique ports, share of flows with no reply, byte and duration averages). A random forest scores each window. |
| `api/app/pipeline.py` | Combines signature and classifier signals and decides when to block. A high severity signature blocks at once. A medium one needs the classifier to agree or repeated alerts. |
| `api/app/response.py` | Blocks with a timeout (1 hour, then 24 hours for repeat offenders). Has `off`, `dry-run`, `simulated` and `enforce` modes, an allowlist, and never passes unparsed input to `nft`. |
| `web/` | Next.js, TypeScript and Tailwind. Overview, alerts, blocked sources, and a detection analysis page comparing signatures, classifier, and both together. |

The sensor sits before the firewall, so detectors keep scoring traffic from a blocked source. That keeps the signature versus classifier comparison fair even after an early block.

## Run the demo

```bash
docker compose up --build        # dashboard on http://localhost:3000, API on :8000
```

Without Docker:

```bash
cd api && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && uvicorn app.main:app --port 8000
cd web && npm install && npm run dev
```

Use **Simulate attack** in the header to launch one yourself and watch it get detected and blocked.

## Run the lab (Linux Docker host)

```bash
docker compose -f lab/docker-compose.lab.yml up --build
docker compose -f lab/docker-compose.lab.yml exec attacker attack scan   # also: bruteforce sqli dns flood all
```

Suricata shares the victim's network namespace. The API shares it too, so the nftables drop rule applies to the victim. The attack scripts refuse any target outside `10.0.1.0/24`. The victim has weak credentials on purpose, so keep the lab network closed.

Set `NETWATCH_API_KEY` before using the unblock button in live mode.

## Deploy the hosted demo

1. **API** on Render: connect the repo and use `render.yaml`. Set `NETWATCH_CORS` to your Vercel URL.
2. **Dashboard** on Vercel: import the repo, set the root directory to `web`, and set `NEXT_PUBLIC_API_URL` to the Render URL.

The free Render tier sleeps when idle, and the API replays 24 hours of history on start (about ten seconds), so the first visit after a nap is slow.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/stats?hours=` | Totals, median time to block, counts by type and country |
| `GET /api/timeline?hours=` | Alerts and blocks per hour |
| `GET /api/alerts` | Recent alerts, filterable by type and response |
| `GET /api/blocks` · `POST /api/blocks/{ip}/unblock` | Active blocks and manual unblock |
| `GET /api/compare?hours=` | Precision and recall for signature, classifier, and hybrid detection |
| `GET /api/stream` | Server-sent events: `alert`, `block`, `unblock` |
| `POST /api/simulate` | Demo mode only: launch a simulated attack |

Settings are environment variables, listed in `api/app/config.py`.

## Tests

```bash
cd api && pip install -r requirements-dev.txt && python -m pytest -q     # 26 tests
cd web && npx tsc --noEmit
```

## Limits to know about

- **Every accuracy figure comes from simulated traffic.** The classifier is trained on the simulator's flows and scored on held-out simulated episodes, so the numbers show the pipeline working, not how it would do on a real network. To go further, retrain on a labelled capture such as CIC-IDS2017 by mapping its flow records into the features in `api/app/ml.py`.
- The authorised-scanner case in the simulator is indistinguishable from an attack by design. That is why the allowlist exists.
- The Suricata rules and the Docker lab were written without a Suricata install or Docker daemon to test against. Run `suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules` first and expect to adjust the rules.
- GeoIP uses a small table for the demo's reserved address range. Mount a GeoLite2 database and set `NETWATCH_GEOIP_DB` for real lookups.

## Ideas for next

LLM incident triage that groups alerts and maps them to ATT&CK, a Cowrie honeypot feeding real attacks, and a Grafana export of the EVE data.
