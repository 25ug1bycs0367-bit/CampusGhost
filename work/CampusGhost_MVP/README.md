# CampusGhost MVP — Role-Based Campus Access Security

CampusGhost is a local hackathon prototype that investigates whether campus-platform permissions are still justified by a person's current relationship and institutional role. It correlates pseudonymous lifecycle records with permissions, checks for expired access, checks for excessive permissions against a role-based least-privilege policy, and creates a ranked report for an administrator.

All bundled records are fictional. Platform data is simulated in local JSON fixtures. The included Contineo Portal is an **LMS example only**; this ZIP does not connect to a real Contineo installation or to any real college system.

## What this version includes

- A pseudonymous investigation dashboard with no people directory.
- Four simulated platform sources: Contineo Portal (LMS), Department Drive, Project Repository and Research Portal.
- Fictional students, project members, research assistants, interns, current faculty and former faculty.
- Two current faculty examples with course-level Contineo permissions; one also has an unnecessary portal-administrator permission.
- Two former faculty examples whose employment has ended but whose Contineo accounts and permissions remain active.
- A role-based least-privilege check. For example, a Faculty member may keep course-instructor or course-grader access, while portal-administrator, system-administrator or broad student-record permissions are flagged for review.
- Expired-permission and lifecycle checks, including employment ended, project exit and internship completed.
- A separate password-protected administrator portal that compares pseudonymous references with fictional identity mappings, displays institutional roles and permissions, and can revoke only grants flagged by the latest investigation.
- Simulated revocation that changes only the local JSON fixture, updates the encrypted SQLite record after connector confirmation, and writes an audit entry.
- AES-256-GCM encryption for identity, account, permission, lifecycle, investigation and audit payloads at rest.
- A generic HTTPS JSON connector scaffold for future institution-authorised integration. Live connections are disabled by default.

## Demo accounts and access examples

The local seed data includes:

| Fictional person | Current relationship | Contineo access example | Expected investigation result |
|---|---|---|---|
| Dr. Ananya Rao | Current faculty | Course Instructor + Portal Administrator | Flag the Portal Administrator grant as excessive; keep the course-level grant unflagged |
| Dr. Vikram Shah | Current faculty | Course Instructor + Course Grader | Retain, subject to the institution's policy |
| Dr. Rohan Iyer | Former faculty; employment ended | Course Instructor + Student Records Administrator still active | Flag all remaining active grants for administrator review |
| Dr. Kavya Menon | Former faculty; resigned | Course Grader still active | Flag the remaining active grant for administrator review |

These are fictional identities and access records created for demonstration. They are not records from an actual college or Contineo portal.

## How the role-based check works

CampusGhost retrieves the institutional role from its dedicated encrypted role field and compares it with the access roles returned by the simulated connectors. For the Faculty role on Contineo Portal, the demo policy allows course-scoped roles such as `Course Instructor`, `Course Grader` and `Course Viewer`. Elevated or broad roles such as `Portal Administrator`, `System Administrator` and `Student Records Administrator`, and restricted resources such as `All Student Records`, are flagged.

A separate lifecycle rule flags remaining permissions when employment has ended. Thus, a former faculty member is not treated as an active faculty member merely because their Contineo account is still enabled.

**Policy limitation:** The bundled role matrix is a transparent demo policy, not an official Contineo permission catalogue or an institution-approved access policy. A real college must provide and approve its own role-to-resource matrix, employment events and identity mapping before live use. The agent recommends; an administrator reviews and confirms any simulated revoke.

## Data flow

```text
Contineo Portal (LMS) JSON fixture ─┐
Department Drive JSON fixture ──────┤
Project Repository JSON fixture ───┼──> connector adapters
Research Portal JSON fixture ───────┘          |
                                               v
                                  validate + pseudonymise + encrypt
                                               |
                                               v
                                     encrypted SQLite records
                                               |
                         pseudonymous case reference ONLY
                                               v
                  LangGraph + local Qwen3  (AGENT-LED INVESTIGATION)
                    |   chooses tools, reads evidence, picks verdict
                    v
        allowlisted read-only Python tools (categorical outputs)
                    |
                    v
   Python verification: evidence ledger + independent rule check
   (may only downgrade to ESCALATE or ADD flags - never invent a revoke)
                    |
                    v
          authenticated admin approval
                    |
                    v
       Python connector + verification
                    |
                    v
            audit log + dashboard
```

## Privacy and encryption notes

- The common `person_ref` is an institution-issued opaque reference in the fixture. CampusGhost converts it into a keyed pseudonymous token such as `CG-P-...`.
- Platform account IDs and identity attributes are encrypted before database storage. The normal dashboard and findings use pseudonymous references.
- Normal detection and AI evidence tools do not decrypt `identity_enc`. Institutional role is stored separately in `institutional_role_enc`. Only the authenticated admin review route decrypts the actual identity mapping; the authenticated revocation path decrypts the required external account identifier only after an admin approves a flagged permission.
- AES-GCM encryption at rest is not homomorphic encryption. Python does not compare raw AES ciphertext. The application decrypts the necessary data inside the trusted backend, validates it and stores protected results.
- The AI agent uses a separate database evidence interface. That interface does not select or decrypt `identity_enc`, external account IDs, usernames or email fields. Institutional role is stored separately in `institutional_role_enc` so the agent evidence tools do not need to open the identity mapping.
- The local encryption key is created at `data/campusghost.key` on first run and is excluded from Git. Keep the database and key protected; losing the key can make stored data unreadable.

## Admin portal login

For this local hackathon demo:

- **Username:** `admin`
- **Password:** `zxcvbnm@123`

The password can be overridden with `CAMPUSGHOST_ADMIN_PASSWORD`. The bundled password is for the isolated local demonstration only. Do not expose this app to a public network or use the demo credential for a real institution. Before production, use a managed identity provider or securely hashed passwords, role-based administrator accounts, HTTPS-only cookies, rate limiting, CSRF protection on all state-changing routes, secrets management and an institution-approved identity-verification process.

## Run on Windows (AI agent-led)

Install and start Ollama for Windows first, then pull the configured local model:

```powershell
ollama pull qwen3:4b
```

Open PowerShell in the extracted `CampusGhost_MVP` folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-ai.txt
$env:CAMPUSGHOST_USE_OLLAMA = "1"
$env:CAMPUSGHOST_AGENT_MODE = "led"
$env:CAMPUSGHOST_AI_STRICT = "1"
$env:OLLAMA_MODEL = "qwen3:4b"
.\.venv\Scripts\python.exe app.py
```

Strict mode never substitutes a rule-based verdict when the AI agent fails; affected cases are escalated for administrator review. The agent-led Windows launcher uses this mode automatically. The admin demo password is built into this local demo configuration, so no extra environment variable is required. To override it in the current PowerShell window:

```powershell
$env:CAMPUSGHOST_ADMIN_USERNAME = "admin"
$env:CAMPUSGHOST_ADMIN_PASSWORD = "your-new-local-password"
.\.venv\Scripts\python.exe app.py
```

Open:

- Main dashboard: `http://127.0.0.1:5000/`
- Admin portal: `http://127.0.0.1:5000/admin/login`

Keep the terminal open while using the app. Press `Ctrl+C` to stop the server. Alternatively, double-click `run_windows.bat` from the project folder; it installs dependencies and launches the local demo using the requested admin credentials.

## Demo sequence

1. Open the main dashboard and click **Sync platform data**.
2. Click **Investigate everyone**.
3. Review the ranked pseudonymous findings. Dr. Ananya Rao should have one excessive Contineo permission flagged while the course-instructor grant remains unflagged. Dr. Vikram Shah should be retained under the bundled demo rules. The two former faculty should be flagged because their employment ended while Contineo access remains active.
4. Open the Admin Portal and sign in with the demo credentials above.
5. Select a case, compare the pseudonymous reference with the fictional identity and institutional role, inspect the permission list, and revoke only a flagged grant.
6. Return to the main dashboard and inspect the audit log. The simulated connector changes only the local fixture.
7. Click **Reset demo data** to restore the fictional data before another demonstration.

## Automated tests

From the project folder, run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The test suite covers connector synchronisation, encryption, pseudonymous correlation, lifecycle findings, excessive faculty permissions, former-faculty access, admin identity comparison and simulated revocation.

`tests/test_agent_led.py` covers the agent-led mode using a scripted stand-in for Qwen3 (`tests/fake_langgraph.py`), so it needs neither Ollama nor LangGraph. It checks that the agent receives only the case reference, that all eight seeded cases reach the expected outcome, and that lazy, fabricating, partial and garbled agents are escalated or corrected. **These tests prove the verification logic, not Qwen3's own quality**; run the real model once with Ollama to see how it behaves.

## Future authorised integration

The project contains a generic HTTPS JSON connector scaffold. A real integration requires the institution's written authorisation, Contineo or other platform API documentation, scoped credentials, an identity-correlation mechanism and a platform-specific adapter. No real Contineo API endpoint, account or credential is included here. Do not probe or test against a college system or third-party service without explicit authorisation. For the hackathon, demonstrate only with the included local fixtures.

## Qwen3 agentic workflow (optional local AI)

When enabled, the investigation is **done by the AI agent** (Qwen3 through Ollama and LangGraph), not by fixed rules.

### Who does what

| Step | Agent-led mode (default when AI is on) |
|---|---|
| Starting information | The agent gets **only** a pseudonymous case reference (`CG-P-...`). No findings, no flagged permissions. |
| Gathering evidence | **Qwen3** decides which read-only tools to call, in what order, and for which permission. |
| Reaching a verdict | **Qwen3** returns `REVOKE`, `RETAIN` or `ESCALATE`, a reason code, and the exact permission references it wants revoked. |
| Checking the verdict | **Python** verifies it. It never leads and never invents a revoke. |
| Final action | A **human administrator** approves any revocation. |

Python verifies the agent in two independent layers:

1. **Evidence ledger** (`agentic_workflow.py`). Only tools the agent actually called count. A proposed revocation survives only if the agent's own results support it (relationship ended, permission expired, or `check_permission_policy` returned `EXCESSIVE`). A `RETAIN` is rejected if the agent's own evidence shows risk, or if it skipped a required check. A reason code that contradicts the action is rejected.
2. **Independent cross-check** (`agent.py`). The original rule-based detection still runs separately. It can downgrade a verdict to `ESCALATE` (for example when the agent says `RETAIN` but the rules disagree, or the agent names permissions the rules do not confirm). It can also **add** flags the agent missed, which are labelled in the evidence list for the administrator. It can never turn a non-revoke into a revoke on its own.

### Settings

| Variable | Meaning |
|---|---|
| `CAMPUSGHOST_USE_OLLAMA=1` | Turn the Qwen3/LangGraph agent on. Off means the Python rule-based workflow only. |
| `CAMPUSGHOST_AGENT_MODE` | `led` (default): the agent gets only the case reference. `assisted`: Python also passes its findings as hints (the previous behaviour). |
| `CAMPUSGHOST_AI_STRICT=1` | If the agent cannot finish (Ollama down, timeout), send the case to an administrator as `ESCALATE` instead of silently issuing the rule-based verdict. |
| `OLLAMA_MODEL` | Qwen3 model tag, default `qwen3:4b`. Non-Qwen3 names are refused. |

The dashboard shows which mode produced each result ("agent-led", "assisted" or "rule-based fallback"), so a fallback is never mistaken for an AI investigation.

### Watch the agent investigate in the terminal

```powershell
..\..\.venv\Scripts\python.exe check_ai.py                 # is everything ready?
..\..\.venv\Scripts\python.exe run_agent_investigation.py   # all cases, live tool-call trace
..\..\.venv\Scripts\python.exe run_agent_investigation.py 7 # only person id 7
```

It prints each tool Qwen3 chooses, each tool result, the agent's verdict and a summary table. Results are saved, so they also appear in the web dashboard and admin portal.

### Quick start (Windows)

Install [Ollama](https://ollama.com/download), open it, run `ollama pull qwen3:4b`, then double-click **`run_agent_windows.bat`**. It enables agent-led mode with strict failure handling. The manual steps are below.

Install and enable it on Windows after the normal project setup:

```powershell
# From the CampusGhost_MVP folder. If your virtual environment is one folder
# level above work\CampusGhost_MVP, use ..\..\.venv as shown here.
..\..\.venv\Scripts\python.exe -m pip install -r requirements-ai.txt

# If .venv is inside CampusGhost_MVP instead, use this command:
# .\.venv\Scripts\python.exe -m pip install -r requirements-ai.txt

# Install Ollama separately, open the Ollama app, then pull the local model
ollama pull qwen3:4b

# In the same PowerShell window used to launch the app
$env:CAMPUSGHOST_USE_OLLAMA = "1"
$env:OLLAMA_MODEL = "qwen3:4b"
$env:CAMPUSGHOST_AI_STRICT = "1"   # optional: never fall back silently to the rules
..\..\.venv\Scripts\python.exe app.py
```

If `CAMPUSGHOST_USE_OLLAMA` is not set to `1`, the app uses the Python rule-based workflow and does not call Qwen3. Ollama must be running locally. The application calls only `http://127.0.0.1:11434/api/chat`; it has no setting for a remote model host.

### Strict AI data boundary

Performance and progress safeguards in this build:

- Qwen3 extended thinking is disabled for this bounded evidence-gathering task (`think: false`).
- Each local Ollama request has a 600-second timeout by default (`OLLAMA_TIMEOUT_SECONDS`, 10-600), accommodating slower local hardware. Strict mode escalates cases when the agent cannot complete a verifiable decision. Run `python check_ai.py` to diagnose why the agent cannot run.
- Each case is limited to 6 LangGraph reasoning turns and 12 successful tool calls (up to 4 tool calls per model turn).
- Identical tool requests for the same case are skipped; Qwen3 can still dynamically select different tools and check different permission references.
- While **Investigate everyone** runs, the dashboard polls a progress endpoint and displays the current pseudonymous case reference and completed/total count. No identity fields are included in progress responses.

In agent-led mode the Qwen3 model receives only: (1) a pseudonymous person reference, (2) descriptions and JSON schemas for five read-only tools, and (3) categorical tool results. (In `assisted` mode it also receives Python detection codes and counts.) The tool results use categories such as `FORMER_FACULTY`, `ADMINISTRATOR`, `CONTINEO_LMS`, `STUDENT_RECORDS_OR_ADMIN` and pseudonymous permission references. They do not return names, email addresses, departments, external platform account IDs, usernames, raw lifecycle descriptions, raw permission/resource labels, database row IDs, encrypted blobs or encryption keys. The model's final decision is limited to `REVOKE`, `RETAIN` or `ESCALATE`, a Python-mapped reason code, and a list of `CG-G-...` permission references that Python validates against the case.

The agent's tool registry is allowlisted and read-only. It has no identity-decryption, admin-review, filesystem, arbitrary database, connector-revocation or permission-changing tool. Tool calls are restricted to the current pseudonymous case, validated against exact argument schemas and bounded by iteration/tool-call limits. Tool output is checked against a denylist of sensitive fields before it is returned to Qwen3.

The identity mapping is stored separately in `identity_enc`. A new `institutional_role_enc` field stores the institutional role separately. Normal Python detection and agent evidence queries use `institutional_role_enc`, `campus_status_enc` and permission/lifecycle payloads; they do not select or decrypt `identity_enc`. Only the authenticated admin review path decrypts `identity_enc`. The external platform account identifier is decrypted only inside the authenticated, approved revocation path. The Python backend, not Qwen3, holds the encryption key.

This is a strong application-level separation, not a mathematical guarantee against compromise of the host computer, Python process, Ollama process or operating system. Keep the prototype local, use fictional data, protect the host and key file, and do not expose Ollama or Flask to an untrusted network. Before production use, place the model process in a separately restricted OS/container boundary and perform an independent security review.

### Agent investigation tools

- `get_lifecycle_evidence`: returns relationship categories and lifecycle event types/dates.
- `get_active_permission_inventory`: returns pseudonymous permission references and categorical platform/resource/role/expiry labels.
- `check_permission_policy`: runs the Python least-privilege policy for one permission.
- `check_permission_expiry`: checks whether one permission is expired, valid or has no expiry.
- `check_research_retention_exception`: checks the known graduate research-assistant exception.

Qwen3 selects among these tools dynamically. Python executes the selected function and returns only its validated result. The graph has no revocation tool: a recommendation must pass the Python verification above and then an authenticated human admin approval before the existing connector revocation route can execute.
