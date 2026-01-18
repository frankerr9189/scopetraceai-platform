# ScopeTraceAI Platform

ScopeTraceAI is an AI-powered requirements, testing, and Jira governance platform designed for multi-tenant enterprise teams.

## Repository Structure

The platform consists of four main components:

- **ai-testing-agent-UI** — React/Vite frontend application (Agent Hub) that provides the unified user interface for all platform services
- **ai-testing-agent** — Test Plan Generation service that creates comprehensive test plans from requirements and tickets
- **ai-sr-business-req-analyst** — Business Requirements Analysis service that extracts and structures requirements from various input sources
- **jira-writeback-agent** — Jira writeback and ticket creation service that manages integration with Jira for ticket creation and updates

## Architecture Overview

The ScopeTraceAI platform follows a microservices architecture with strict tenant isolation:

- **Multi-tenant architecture** enforced via JWT tokens containing `tenant_id` claims
- **PostgreSQL** serves as the single source of truth for all tenant data, user accounts, integrations, and usage tracking
- Each agent runs as an **independent service** with its own API endpoints and business logic
- The **Agent Hub UI** orchestrates all interactions, providing a unified interface that communicates with all backend services
- **Usage tracking and entitlement enforcement** are implemented across all agents to ensure proper access control and subscription management
- Tenant data is isolated at the database query level, ensuring no cross-tenant data leakage

## Prerequisites

Before setting up the platform, ensure you have the following installed:

- **Node.js** 18 or higher
- **Python** 3.9 or higher
- **PostgreSQL** (version 12 or higher recommended)
- **Git**

## Environment Configuration

Each service requires its own `.env` configuration file. These files are not committed to the repository for security reasons.

Template files (`.env.example`) are provided in each service directory to guide configuration. Copy these to `.env` and populate with your actual values.

Common environment variables used across services:

- `DATABASE_URL` — PostgreSQL connection string (required for services that access the database)
- `JWT_SECRET` — Secret key for JWT token signing and verification (required for authentication)
- `INTEGRATION_SECRET_KEY` — Fernet encryption key for storing sensitive integration credentials (required for credential encryption)
- `OPENAI_API_KEY` — OpenAI API key for AI-powered features (required for services using OpenAI)

Additional service-specific variables are documented in each service's `.env.example` file.

## Running Locally

### Backend Services

Each backend service follows a similar setup pattern:

1. Navigate to the service directory
2. Create a Python virtual environment (if not already present)
3. Activate the virtual environment
4. Install dependencies from `requirements.txt`
5. Copy `.env.example` to `.env` and configure with your values
6. Run the service using the appropriate command for that service

The services can be run independently or together using the provided startup scripts.

### Agent Hub UI

1. Navigate to the `ai-testing-agent-UI` directory
2. Install dependencies using npm or yarn
3. Copy `.env.example` to `.env` and configure API base URLs
4. Run the development server

The UI will connect to the backend services based on the configured API base URLs in the environment variables.

## Authentication & Tenancy

The platform uses JWT-based authentication with tenant isolation:

- **JWT tokens** are issued upon successful login or registration
- Each JWT contains a `tenant_id` claim that identifies the user's organization
- **All data access** is automatically scoped to the tenant_id from the JWT
- **Role-based access control** is implemented with four roles:
  - `user` — Standard user with access to core features
  - `admin` — Administrative user (does not grant admin panel access)
  - `owner` — Tenant owner with full access including admin panel
  - `superAdmin` — Platform super administrator with cross-tenant access
- **Admin control plane** access is restricted to `owner` and `superAdmin` roles only
- Tenant isolation is enforced at the application layer, middleware layer, and database query level

## Trial & Subscription Model

The platform implements a trial-based access model with usage tracking:

- **Trial access** provides limited runs per agent (Requirements, Test Plan, Jira Writeback)
- **Entitlements are enforced server-side** on every request to prevent unauthorized usage
- The **UI reflects remaining usage** in real-time, showing trial counts and subscription status
- When trial runs are exhausted, the system automatically applies a **paywall** that blocks further usage
- **Admin override** is available for support and testing scenarios, allowing administrators to reset trial counts or modify subscription status
- Subscription status is stored per tenant and can be: `Trial`, `Active`, or `Paywalled`

## Deployment Notes

The platform components are designed to be deployed independently:

- **UI** can be deployed to static hosting services (e.g., Vercel, Netlify) or containerized environments
- **Backend services** can be deployed independently to container platforms (e.g., Render, Fly.io, VM instances) or orchestrated together
- **Environment variables** must be configured per service in the deployment environment
- **PostgreSQL** must be reachable from all services that require database access
- Services communicate via HTTP/REST APIs, so network connectivity between services is required
- CORS configuration may need adjustment based on deployment domains

## Security Notes

Security is a core concern in the platform design:

- **Secrets are never committed** to the repository; all sensitive values are stored in environment variables
- **API tokens and credentials** are encrypted at rest using Fernet symmetric encryption before database storage
- **Tenant isolation** is enforced at every layer: JWT validation, middleware, database queries, and business logic
- **Admin endpoints** are role-restricted and require explicit `owner` or `superAdmin` role verification
- **JWT tokens** are signed with a secret key and include expiration times
- All database queries automatically filter by `tenant_id` to prevent cross-tenant data access

## License

© ScopeTraceAI. All rights reserved.
