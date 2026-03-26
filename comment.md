## 🔒 Semgrep Security Scan Results

**Total findings**: 6

### Breakdown by Severity
- **ERROR**: 5
- **WARNING**: 1
### Findings
**python.lang.security.audit.subprocess-shell-true.subprocess-shell-true** — `src/vulnerable_tasks/test_vulnerabilities.py:35` — Found 'subprocess' function 'run' with 'shell=True'. This is dangerous because this call will spawn the command using a shell process. Doing so propagates current shell settings and variables, which makes it much easier for a malicious actor to execute commands. Use 'shell=False' instead. _(Severity: ERROR)_
**semgrep.hardcoded-secrets** — `src/vulnerable_tasks/test_vulnerabilities.py:47` — Hardcoded secret detected. _(Severity: ERROR)_
**semgrep.path-traversal** — `src/vulnerable_tasks/test_vulnerabilities.py:62` — File operation with user-controlled path detected. _(Severity: ERROR)_
**semgrep.insecure-ssl-verification** — `src/vulnerable_tasks/test_vulnerabilities.py:77` — requests.get(..., verify=False) detected. _(Severity: ERROR)_
**semgrep.insecure-deserialization** — `src/vulnerable_tasks/test_vulnerabilities.py:83` — pickle.loads() call detected. _(Severity: ERROR)_
**python.lang.security.audit.formatted-sql-query.formatted-sql-query** — `src/vulnerable_tasks/test_vulnerabilities.py:21` — Detected possible formatted SQL query. Use parameterized queries instead. _(Severity: WARNING)_

📦 Full results available as workflow artifact: 

<!-- AI-SECURITY-FINDINGS -->
