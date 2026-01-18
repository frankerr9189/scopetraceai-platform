# AI Senior Business Requirement Analyst

An AI-powered agent that acts as a Senior Business Requirement Analyst, designed to analyze, validate, and structure business requirements with the expertise of an experienced analyst.

## Overview

This FastAPI application provides an AI agent capable of:

- **Analyzing Business Requirements**: Thoroughly examine and understand business requirements
- **Identifying Gaps**: Detect missing information or incomplete requirements
- **Risk Assessment**: Evaluate potential risks associated with requirements
- **Structured Output**: Provide well-organized, versioned requirement packages
- **Validation**: Enforce invariant rules and ensure requirement quality

## Project Structure

```
ai-sr-business-req-analyst/
├── app/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Environment and constants
│   ├── api/
│   │   └── analyze.py       # POST /analyze endpoint
│   ├── agent/
│   │   ├── analyst.py       # Core orchestration
│   │   ├── prompt.py        # System prompts
│   │   └── rules.py         # Guardrails and prohibitions
│   ├── models/
│   │   ├── requirement.py   # Requirement models
│   │   ├── package.py       # Versioned output models
│   │   └── enums.py         # Status enums
│   ├── services/
│   │   ├── numbering.py     # Deterministic ID generation
│   │   ├── versioning.py    # Version handling
│   │   └── risk_analysis.py # Gap and risk analysis
│   └── validators/
│       └── invariants.py    # Invariant rules enforcement
├── tests/                   # Test directory
├── requirements.txt         # Python dependencies
├── .env.example            # Environment variables template
└── README.md               # This file
```

## Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your OpenAI API key and other settings
   ```

3. **Run the Application**
   ```bash
   uvicorn app.main:app --reload
   ```

## API Endpoints

- `GET /` - Root endpoint
- `GET /health` - Health check
- `POST /api/v1/analyze` - Analyze business requirements (implementation pending)

## Development Status

⚠️ **Note**: This is currently a scaffolding project. Core business logic is not yet implemented. All endpoints and services are placeholders ready for implementation.

## License

[To be determined]

