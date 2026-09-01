# mailMeta

Email header forensics toolkit — analyze `.eml` files or monitor live mailboxes via IMAP. Verifies SPF/DKIM/DMARC against live DNS and scores every message on a 0-100 risk scale.

## Capabilities

- **CLI analysis** — `python3 meta.py -f message.eml`
- **Directory batch** — `python3 meta.py -d ./maildir`
- **Live IMAP monitoring** — background poller auto-analyzes new mail, stores results in SQLite
- **Web dashboard** — FastAPI app with risk filtering, search, CSV export, raw header viewer
- **Live DNS verification** — real SPF mechanism evaluation (ip4/ip6/a/mx/include/redirect/all), cryptographic DKIM signature verification, DMARC policy lookup
- **Risk scoring** — SPF/DKIM/DMARC outcomes + header anomaly heuristics (Reply-To mismatch, brand impersonation, missing Message-ID)

## Install

```bash
pip3 install -r requirements.txt
```

## CLI usage

```bash
python3 meta.py -f test/spoofed.eml          # full DNS verification
python3 meta.py -f test/original.eml --no-dns  # offline header-only
python3 meta.py -d /path/to/mails -j         # batch, JSON output
```

## IMAP monitoring + web dashboard

1. Copy the example config:
   ```bash
   cp mailmeta.example.json mailmeta.json
   ```
2. Edit `mailmeta.json` — set your IMAP host, username, and password (use an app password for Gmail, not your real password).

3. Run the server:
   ```bash
   python3 main.py                # web + monitors
   python3 main.py --web-only     # dashboard only
   python3 main.py --monitor-only # monitors only
   ```

4. Open http://localhost:8000 (bind is `0.0.0.0`, so from another machine on your LAN use that machine's IP).

## Config reference

| Key | Meaning |
|-----|---------|
| `database` | SQLite file path |
| `poll_interval` | seconds between IMAP polls |
| `only_new` | only analyze messages not seen before |
| `web.host` / `web.port` | dashboard bind addr/port |
| `accounts[]` | one entry per mailbox: host, port, username, password, folder, active |

Secrets: `mailmeta.json` is gitignored. Prefer env vars in production.

## Project layout

```
mailmeta/
  analyzer.py     header parsing, IP extraction
  dns_verifier.py SPF/DKIM/DMARC live DNS checks
  pipeline.py     analyze() — end-to-end orchestration
  risk.py         0-100 scoring + findings
  database.py     SQLite persistence
  imap_monitor.py background mailbox poller
  config.py       config loading
web/
  app.py          FastAPI routes + static
  templates/      dashboard.html
  static/         style.css, app.js
meta.py           CLI entrypoint
main.py           server entrypoint
```

## API

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | counts by risk level, account, totals |
| `GET /api/monitors` | IMAP monitor status |
| `GET /api/emails?risk_level=&search=&sort=` | paginated list |
| `GET /api/emails/{id}` | full detail incl. DNS results, received path, findings |
| `GET /api/emails/{id}/raw` | original raw message |
| `DELETE /api/emails/{id}` | delete record |

## Notes / limits (truth in advertising)

- SPF evaluation implements common mechanisms; complex macros (`%{d}`, `%{i}` substitution) beyond a small subset are approximated — rare in practice, but a handful of records may yield permerror/neutral instead of the true result.
- DKIM verification is cryptographic via `dkimpy`.
- DMARC pass requires live SPF/DKIM results, which the tool computes itself. If the mail server's own `Authentication-Results` differs, trust the DNS-computed result — that's the point of verifying independently.
- Risk scoring is heuristic, not a guarantee. High risk ≠ definitely malicious; low risk ≠ definitely safe.

## License

MIT.