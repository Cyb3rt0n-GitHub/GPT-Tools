# GPT-Tools — legacy domain scanner

Early personal experiments by Cyb3rt0n, originally written in 2023. These standalone public prototypes collect evidence; they are not an enterprise assurance platform. They collect TLS and email DNS evidence for domains you are authorised to assess.

## Python version

Requires Python 3.10+, `sslscan` on PATH and the third-party packages in `requirements.txt`. `aha` is no longer required: HTML is generated with escaped evidence.

```bash
sudo apt install sslscan
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Create `domains.txt` containing one hostname per line, for example `example.org`. Blank lines, `#` comments and duplicates are ignored. URLs, ports and command-line options are rejected.

```bash
python legacy_domain_scanner.py domains.txt
# Choose a new report directory:
python legacy_domain_scanner.py domains.txt --output-dir my-results
```

Each run creates a new directory and refuses existing destinations. It contains `results.json`, `domain_results.txt`, `domain_results.html` and `sslscan_results.txt`. Each domain retains its own TLS/DNS evidence, timestamp, errors and commentary. Reports are updated after each completed domain. TLS scans time out after 120 seconds; DNS queries after five seconds. Failed TLS scans do not suppress DNS evidence or subsequent domains. Exit status is nonzero for collection errors or requested AI failures.

### Optional AI commentary

**Off by default.** The normal scan does not contact OpenAI or incur API charges. To opt in, set `OPENAI_API_KEY` securely in your environment, choose a Chat Completions-compatible model available to your account, and run:

```bash
python legacy_domain_scanner.py domains.txt --ai --model YOUR_MODEL_ID
```

Alternatively set `OPENAI_MODEL`. Never put real keys in source files, reports or commits. Opting in sends each domain's DNS and TLS evidence to OpenAI and incurs API usage. Input has a 24,000-character bound (not a token guarantee); evidence is retained in full locally. API errors are recorded without dumping response bodies. AI output is unverified commentary, not findings or instructions to execute. The Go version does not implement AI calls.

API reference: [OpenAI Chat Completions](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create).

## Go version

Requires Go 1.22+ and `sslscan`. No third-party Go packages or API key are needed.

```bash
go test ./...
go run legacy_domain_scanner.go
# Optional new output directory (input remains domains.txt):
go run legacy_domain_scanner.go my-go-results
```

Runs sequentially to bound scanner load. Writes raw TLS evidence, DNS text and escaped HTML into a new directory. AI commentary is explicitly marked unimplemented. A failed scan is preserved and the final exit status is nonzero. DNS query failures are recorded as unknown in the report.

## Interpretation limits

- Matching TXT records indicate presence, not valid policy or effective protection.
- Only `default._domainkey` is checked for DKIM. Other selectors may exist; empty results do not prove DKIM is disabled.
- MTA-STS checks only the DNS advertisement; no HTTPS policy or mail enforcement validation is performed.
- DNS timeouts and resolver failures are unknowns, not evidence of absent controls.
- TLS scans target the hostname's default endpoint; they do not assess all ports, SMTP STARTTLS or every backend.
- Review output before publishing it. Public source does not mean collected target evidence should be public.

## Regression checks

```bash
python -m unittest discover -s tests -v
go test ./...
```

Tests use synthetic data and mocked external services. No real target scans or paid AI calls are required.
