# CampusGhost
### AI-Powered Intelligent Access Permission Auditor

CampusGhost is an AI-assisted security auditing system designed to identify excessive, outdated, and potentially unauthorized access permissions in campus digital resources.

It helps administrators investigate suspicious access, review permissions, and take appropriate action to improve campus data security.

## Problem Statement

Educational institutions use multiple digital platforms to manage student, faculty, research, and administrative resources.

When students or faculty leave an institution or change their roles, their previous access permissions may remain active. This can result in unauthorized access, excessive permissions, and potential misuse of sensitive information.

CampusGhost aims to address this problem through automated access auditing and AI-assisted investigation.

## Our Solution

CampusGhost collects access-related evidence from connected or simulated campus data sources and analyzes it to identify suspicious or excessive permissions.

The system provides an AI-assisted investigation workflow that helps administrators understand potential security issues and review appropriate actions.

## Key Features

- Access permission auditing
- Detection of excessive or outdated permissions
- AI-assisted security investigation using Qwen3
- Agent-based investigation workflow
- Pseudonymisation of identity information
- AES-256-GCM encryption for database records
- Administrator login and review portal
- Multiple platform integrations
- Security checks and automated tests

## How the AI Agent Works

1. The system collects relevant access evidence from available data sources.
2. The agent receives limited, read-only investigation tools.
3. Qwen3 analyzes the available evidence.
4. The agent investigates possible access-related risks.
5. Findings are presented for administrator review.
6. Administrators can review and decide the appropriate action.

The AI agent does not directly receive decrypted identity information or unrestricted administrative access.

## Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development |
| Flask | Web application |
| HTML | Web page structure |
| CSS | User interface styling |
| JavaScript | Frontend interactions |
| Qwen3 | AI-based analysis |
| LangGraph | Agent workflow orchestration |
| AES-256-GCM | Data encryption |
| SQLite | Database storage |
| Git and GitHub | Version control |

## Project Structure

```text
CampusGhost/
└── work/
    └── CampusGhost_MVP/
        ├── app.py
        ├── agent.py
        ├── agent_tools.py
        ├── agentic_workflow.py
        ├── database.py
        ├── run_agent_investigation.py
        ├── integrations/
        ├── templates/
        ├── static/
        ├── tests/
        ├── requirements.txt
        ├── requirements-ai.txt
        └── README.md
```

## How to Run the Project

### 1. Clone the repository

```bash
git clone https://github.com/25ug1bycs0367-bit/CampusGhost.git
cd CampusGhost
```

### 2. Open the project directory

```bash
cd work/CampusGhost_MVP
```

### 3. Create a virtual environment

```bash
python -m venv .venv
```

### 4. Activate the environment (Windows)

```powershell
.venv\Scripts\activate
```

### 5. Install the dependencies

```powershell
pip install -r requirements.txt
```

For AI agent dependencies and configuration, refer to the detailed project README and requirements-ai.txt.

### 6. Run the application

```powershell
python app.py
```

### 7. Open in your browser

http://127.0.0.1:5000

Admin portal:

http://127.0.0.1:5000/admin/login

## Security and Privacy

- Database records are encrypted at rest.
- Pseudonymous information is used in the investigation workflow.
- AI investigation tools are designed with restricted, read-only access.
- Sensitive identity and encryption information are kept separate from the AI agent.

## Testing

The project includes tests covering application startup, agent functionality, and security restrictions.

## Project Scope

CampusGhost is an academic MVP prototype. It currently uses pseudonymous demonstration data and simulated platform integrations. It is not yet a production deployment connected to a real institution's systems.

## Future Enhancements

- Integration with real campus platforms
- More advanced access anomaly detection
- Improved administrator dashboards
- Automated access review workflows
- Additional security monitoring capabilities

## Detailed Documentation

For the detailed implementation, setup instructions, and technical workflow, see:

[CampusGhost MVP README](work/CampusGhost_MVP/README.md)

---

**CampusGhost - Making Campus Digital Access Safer.**
