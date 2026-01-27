# SOC Chatbot - Multi-Agent Security Operations Platform

A full-stack security operations chatbot featuring multi-agent architecture with OCSF-normalized data lake integration. Built for agentic SOC operations with specialized AI agents for threat intelligence, triage, incident response, and data analysis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         React Frontend                               │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│   │   Chat   │  │  Agent   │  │  Stats   │  │  Quick Actions   │   │
│   │ Interface│  │  Status  │  │Dashboard │  │    (Triage,etc)  │   │
│   └──────────┘  └──────────┘  └──────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                               │
│   ┌─────────────────────────────────────────────────────────────┐   │
│   │                    Orchestrator Agent                        │   │
│   │    (Intent Classification, Agent Routing, Synthesis)         │   │
│   └─────────────────────────────────────────────────────────────┘   │
│                    ▼           ▼           ▼           ▼            │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐      │
│   │  Query   │  │  Triage  │  │  Threat  │  │   Incident    │      │
│   │  Agent   │  │  Agent   │  │  Intel   │  │   Response    │      │
│   └──────────┘  └──────────┘  └──────────┘  └───────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│              OCSF Normalized Data Lake (1,850+ Events)              │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│   │ Network  │  │ Process  │  │   File   │  │   DNS    │           │
│   │ Activity │  │ Activity │  │ Activity │  │ Activity │           │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

## Features

### Multi-Agent System
- **Orchestrator Agent**: Master coordinator - classifies intent, routes to specialists, synthesizes responses
- **Query Agent**: Natural language to data lake queries - supports search, count, timeline, statistics
- **Triage Agent**: Alert prioritization with scoring based on severity, MITRE ATT&CK techniques, IOCs, critical assets
- **Threat Intel Agent**: IOC enrichment, threat actor attribution, threat landscape analysis
- **Incident Response Agent**: Response playbooks for malware, credential theft, C2, data exfiltration

### OCSF Data Lake
- 1,850+ synthetic security events in Open Cybersecurity Schema Framework (OCSF) format
- Event types: Authentication (500), Network (300), Process (400), File (200), DNS (250)
- 7 data sources: CrowdStrike, Palo Alto, Carbon Black, Cisco Umbrella, SentinelOne, Splunk, Microsoft Defender
- Known threat indicators: malicious IPs, C2 domains, malware hashes
- 158+ alerts with MITRE ATT&CK mapping

### Frontend
- Tactical cyber-themed UI with dark mode
- Real-time chat with agent transparency
- Statistics dashboard
- Quick action buttons
- Session management

## Quick Start

### Local Development

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```

Access at http://localhost:3000

### Docker Deployment

```bash
docker-compose up --build
```

Access at http://localhost

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/chat` | POST | Main chatbot interface |
| `/health` | GET | Health check |
| `/info` | GET | API information |
| `/data-lake/statistics` | GET | Data lake metrics |
| `/data-lake/query` | POST | Execute data lake query |
| `/data-lake/timeline/{entity_type}/{entity_value}` | GET | Entity event history |
| `/alerts` | GET | Get alerts with filters |
| `/alerts/summary` | GET | Alert summary |
| `/agents` | GET | List active agents |

Full API docs at `/docs` (Swagger UI) or `/redoc`

## Sample Interactions

```
User: "Triage my open alerts"
→ TriageAgent returns prioritized queue with risk scores

User: "What do we know about IP 185.220.101.1?"
→ ThreatIntelAgent returns APT28 C2 server attribution

User: "Show me critical events from today"
→ QueryAgent filters data lake, returns formatted results

User: "How should I respond to credential theft?"
→ IncidentResponseAgent provides 9-step playbook

User: "Show me statistics"
→ QueryAgent aggregates data lake metrics
```

## Project Structure

```
soc-chatbot/
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── base_agent.py       # Abstract base, AgentRegistry
│   │   │   ├── query_agent.py      # Data lake queries
│   │   │   ├── triage_agent.py     # Alert prioritization + ThreatIntel
│   │   │   ├── ir_agent.py         # Incident response playbooks
│   │   │   └── orchestrator.py     # Master coordinator
│   │   ├── models/
│   │   │   ├── ocsf_models.py      # OCSF schema classes
│   │   │   └── chat_models.py      # Chat/agent models
│   │   ├── services/
│   │   │   └── data_lake.py        # Normalized data lake
│   │   └── main.py                 # FastAPI application
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # Main application
│   │   └── index.css               # Tactical styling
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
├── docker-compose.yml
└── README.md
```

## Tech Stack

**Backend:**
- FastAPI 0.109.0
- Pydantic 2.5.3
- Uvicorn 0.27.0
- Python 3.11+

**Frontend:**
- React 18.2.0
- Vite 5.0.8
- Tailwind CSS 3.4.1
- Lucide React icons

**Deployment:**
- Docker & Docker Compose
- Nginx (frontend)

## Configuration

**Backend Environment:**
- `PYTHONUNBUFFERED=1` - Unbuffered logging

**Frontend (vite.config.js):**
- Dev server: port 3000
- API proxy: /api → http://localhost:8000

## License

MIT

---

Built as part of the Agentic SOC Platform development.
