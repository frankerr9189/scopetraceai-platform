# AppScopeTraceAI - Project Structure

## Overview

This is a multi-service SaaS application for AI-powered business requirement analysis, test plan generation, and Jira integration. The system consists of four main components that work together to analyze requirements, generate test plans, and manage traceability.

## System Architecture

```
appscopetraceai/
├── ai-sr-business-req-analyst/     # Business Requirements Analysis Service (Port 8000)
├── ai-testing-agent/               # Test Plan Generation Service (Port 5050)
├── ai-testing-agent-UI/            # React/TypeScript Frontend (Port 5173)
├── jira-writeback-agent/           # Jira Write-Back Service (Port 8001)
└── [utility scripts and configs]
```

---

## 1. AI Senior Business Requirement Analyst

**Purpose**: AI-powered agent that analyzes, validates, and structures business requirements with expert-level analysis capabilities.

**Technology**: FastAPI (Python)

**Port**: 8000

### Directory Structure

```
ai-sr-business-req-analyst/
├── app/
│   ├── main.py                     # FastAPI entry point
│   ├── config.py                   # Environment and constants
│   │
│   ├── agent/                      # Core AI agent logic
│   │   ├── analyst.py             # Main orchestration logic
│   │   ├── prompt.py              # System prompts for LLM
│   │   └── rules.py               # Guardrails and prohibitions
│   │
│   ├── api/                        # API endpoints
│   │   ├── analyze.py             # POST /analyze endpoint
│   │   ├── overrides.py           # Override management
│   │   ├── presentation.py        # Presentation formatting
│   │   └── scope_status.py        # Scope status tracking
│   │
│   ├── models/                     # Data models
│   │   ├── requirement.py         # Requirement data models
│   │   ├── package.py             # Versioned output packages
│   │   ├── intermediate.py        # Intermediate processing models
│   │   └── enums.py               # Status and type enums
│   │
│   ├── services/                   # Business logic services
│   │   ├── numbering.py           # Deterministic ID generation
│   │   ├── versioning.py           # Version handling
│   │   ├── risk_analysis.py        # Gap and risk analysis
│   │   ├── quality_scoring.py      # Quality assessment
│   │   ├── analysis_mapper.py      # Analysis result mapping
│   │   ├── attachment_parser.py    # Document parsing
│   │   ├── jira_client.py          # Jira API integration
│   │   └── llm_client.py           # LLM API client
│   │
│   └── validators/                 # Validation logic
│       └── invariants.py           # Invariant rules enforcement
│
├── tests/                          # Test files
│   ├── test_analyst.py
│   ├── test_config.py
│   ├── test_guardrails.py
│   ├── test_humanization.py
│   ├── test_no_test_language.py
│   ├── test_pattern_a.py
│   ├── test_subtask_generation.py
│   └── test_ticket_packaging.py
│
├── requirements.txt                # Python dependencies
├── README.md                       # Service documentation
├── venv/                           # Python virtual environment
└── [sample/test JSON files]        # Test data files
```

### Key Features
- Analyzes business requirements with AI
- Identifies gaps and missing information
- Performs risk assessment
- Provides structured, versioned requirement packages
- Enforces invariant rules and quality validation

---

## 2. AI Testing Agent

**Purpose**: Flask-based backend service that generates test plans and requirement traceability matrices (RTM) from JIRA tickets using OpenAI's LLM.

**Technology**: Flask (Python)

**Port**: 5050

### Directory Structure

```
ai-testing-agent/
├── backend/
│   ├── app.py                      # Flask application entry point
│   ├── db.py                       # Database configuration
│   ├── models.py                   # SQLAlchemy models
│   ├── rtm.py                      # RTM generation logic
│   │
│   ├── services/                   # Business logic services
│   │   ├── jira_client.py         # Jira API integration
│   │   ├── persistence.py         # Data persistence layer
│   │   └── coverage_enforcer.py    # Coverage enforcement logic
│   │
│   ├── data/                       # Data storage
│   │   ├── app.db                 # SQLite database
│   │   └── artifacts/              # Generated artifacts (JSON files)
│   │
│   ├── tests/                      # Test files
│   │   ├── test_actor_attribution.py
│   │   ├── test_artifact_endpoints.py
│   │   ├── test_auth.py
│   │   ├── test_compliance.py
│   │   ├── test_coverage_enforcer.py
│   │   ├── test_execution_report.py
│   │   ├── test_guardrails.py
│   │   ├── test_jira_writeback.py
│   │   ├── test_lifecycle_separation.py
│   │   ├── test_persistence_integration.py
│   │   ├── test_persistence.py
│   │   ├── test_requirement_invariants.py
│   │   ├── test_review_approval.py
│   │   ├── test_rtm_informational.py
│   │   ├── test_run_attribution.py
│   │   └── test_runs_endpoints.py
│   │
│   ├── requirements.txt            # Python dependencies
│   ├── start_server.sh             # Server startup script
│   └── venv/                       # Python virtual environment
│
├── frontend/                       # Legacy frontend (React/JSX)
│   ├── index.html
│   ├── package.json
│   └── src/
│       ├── App.jsx
│       ├── App.css
│       ├── index.css
│       └── main.jsx
│
├── ARCHITECTURE.md                 # Architecture documentation
├── CHANGELOG.md                    # Change log
├── COMPLIANCE.md                   # Compliance documentation
├── rtm_export.json                 # Sample RTM export
├── rtm.csv                         # Sample RTM CSV
└── venv/                           # Root-level virtual environment
```

### Key Features
- Generates test plans from JIRA tickets
- Creates Requirement Traceability Matrix (RTM)
- Calculates quality scores for requirements
- Provides coverage confidence metrics
- Maintains audit metadata for compliance
- Supports deterministic test ID generation

### API Endpoints
- `POST /generate-test-plan` - Generate test plan from tickets
- `GET /export/rtm` - Export RTM as CSV
- `GET /export/test-plan` - Export test plan as JSON

---

## 3. AI Testing Agent UI

**Purpose**: Modern React/TypeScript frontend for the AI Testing Agent service.

**Technology**: React + TypeScript + Vite + Tailwind CSS

**Port**: 5173

### Directory Structure

```
ai-testing-agent-UI/
├── src/
│   ├── main.tsx                    # Application entry point
│   ├── App.tsx                     # Main app component
│   ├── index.css                   # Global styles
│   │
│   ├── components/                 # React components
│   │   ├── Header.tsx              # App header
│   │   ├── Sidebar.tsx             # Navigation sidebar
│   │   ├── Background.tsx          # Background component
│   │   │
│   │   ├── LoginPage.tsx           # Authentication page
│   │   │
│   │   ├── TicketInputPanel.tsx    # Ticket input interface
│   │   ├── TicketsView.tsx         # Tickets display
│   │   ├── TicketBreakdownView.tsx # Ticket breakdown
│   │   │
│   │   ├── TestPlanPage.tsx        # Test plan page
│   │   ├── TestPlanView.tsx        # Test plan display
│   │   │
│   │   ├── RequirementsPage.tsx    # Requirements page
│   │   ├── RequirementsView.tsx    # Requirements display
│   │   ├── RequirementCentricTestView.tsx # Requirement-centric view
│   │   │
│   │   ├── RTMTable.tsx            # RTM table component
│   │   │
│   │   ├── RunHistoryPage.tsx      # Run history page
│   │   ├── AuditMetadataView.tsx   # Audit metadata display
│   │   │
│   │   └── ui/                     # UI component library
│   │       ├── button.tsx
│   │       ├── card.tsx
│   │       ├── badge.tsx
│   │       └── tabs.tsx
│   │
│   ├── services/                   # API services
│   │   └── api.ts                  # API client
│   │
│   ├── lib/                        # Utility libraries
│   │   └── [utility files]
│   │
│   └── config.ts                   # Configuration
│
├── index.html                      # HTML entry point
├── package.json                    # Node.js dependencies
├── vite.config.ts                  # Vite configuration
├── tailwind.config.js              # Tailwind CSS configuration
├── tsconfig.json                   # TypeScript configuration
├── tsconfig.node.json              # TypeScript node config
├── postcss.config.js               # PostCSS configuration
├── README.md                       # Documentation
└── QUICKSTART.md                   # Quick start guide
```

### Key Features
- Modern, responsive UI
- Ticket input and management
- Test plan visualization
- Requirements view
- RTM table display
- Run history tracking
- Audit metadata viewing

---

## 4. Jira Write-Back Agent

**Purpose**: Deterministic Jira write-back service that rewrites existing Jira issues using pre-approved, scope-locked outputs from upstream agents.

**Technology**: FastAPI (Python)

**Port**: 8001

### Directory Structure

```
jira-writeback-agent/
├── main.py                         # FastAPI entry point
│
├── api/                            # API endpoints
│   ├── rewrite.py                 # Jira rewrite endpoint
│   └── __init__.py
│
├── models/                         # Data models
│   ├── writeback_event.py         # Writeback event model
│   └── __init__.py
│
├── services/                       # Business logic
│   ├── jira_client.py             # Jira API client
│   ├── audit_logger.py            # Audit logging service
│   └── __init__.py
│
├── src/
│   └── jira_writeback_agent/      # Package source
│       └── [package files]
│
├── tests/                          # Test files
│   ├── test_create.py
│   ├── test_mapping.py
│   └── __init__.py
│
├── audit_logs/                     # Audit log files
│   ├── audit_2026-01-07.jsonl
│   ├── audit_2026-01-08.jsonl
│   ├── audit_2026-01-11.jsonl
│   └── audit_2026-01-14.jsonl
│
├── pyproject.toml                  # Python project configuration
└── README.md                       # Documentation
```

### Key Features
- **Deterministic operations only** - No AI or heuristics
- **Never creates issues** - Only rewrites existing ones
- **Fully audited** - All mutations logged
- **Approval required** - Explicit approval for all changes
- **Scope-locked** - Uses pre-approved outputs only

---

## 5. Root-Level Files

```
appscopetraceai/
├── README_STARTUP.md               # Service startup guide
├── start_all_services.sh           # Script to start all services
├── stop_all_services.sh            # Script to stop all services
├── check_services.sh               # Service health check script
├── SaasAIStudio.code-workspace     # VS Code workspace config
├── TestPlanCreationDocumentation.pages # Documentation
└── opengraph-image.png             # Open graph image
```

---

## Service Communication Flow

```
┌─────────────────────┐
│  Business Req       │
│  Analyst (8000)     │
│  - Analyzes reqs    │
│  - Validates        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Testing Agent      │
│  (5050)             │
│  - Generates tests  │
│  - Creates RTM      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Jira Writeback     │
│  Agent (8001)       │
│  - Writes to Jira   │
│  - Audits changes   │
└─────────────────────┘
           ▲
           │
┌──────────┴──────────┐
│  UI (5173)          │
│  - User interface   │
│  - Visualization    │
└─────────────────────┘
```

---

## Technology Stack Summary

### Backend Services
- **Python 3.9+**
- **FastAPI** (Business Req Analyst, Jira Writeback)
- **Flask** (Testing Agent)
- **SQLAlchemy** (Database ORM)
- **OpenAI API** (LLM integration)
- **Jira API** (Jira integration)

### Frontend
- **React 18+**
- **TypeScript**
- **Vite** (Build tool)
- **Tailwind CSS** (Styling)

### Data Storage
- **SQLite** (Testing Agent database)
- **JSON files** (Artifacts and exports)
- **JSONL files** (Audit logs)

---

## Environment Variables

### Common
- `OPENAI_API_KEY` - OpenAI API key for LLM services

### Jira Integration
- `JIRA_BASE_URL` - Jira instance URL
- `JIRA_EMAIL` / `JIRA_USERNAME` - Jira user credentials
- `JIRA_API_TOKEN` - Jira API token

### Environment
- `ENVIRONMENT` - Deployment environment (production/staging/development)

---

## Quick Start Commands

```bash
# Start all services
./start_all_services.sh

# Stop all services
./stop_all_services.sh

# Check service health
./check_services.sh
```

---

## Service URLs

- **BA Requirements Agent**: http://localhost:8000
- **Jira Writeback Agent**: http://localhost:8001
- **Testing Agent**: http://localhost:5050
- **UI**: http://localhost:5173

---

## Key Design Principles

1. **Deterministic Operations**: Test IDs and outputs are deterministic given the same inputs
2. **Audit Trail**: All operations are logged with full metadata
3. **Separation of Concerns**: Clear separation between test content and audit metadata
4. **Compliance**: Built-in compliance features for requirement traceability
5. **No AI in Writeback**: Jira writeback agent is deterministic only, no AI/heuristics
