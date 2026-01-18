# Quick Start Guide

## Prerequisites

1. **Node.js 18+** installed
2. **Backend API** running at `http://localhost:5050`

## Setup Steps

1. **Install dependencies:**
   ```bash
   cd ai-testing-agent-ui
   npm install
   ```

2. **Configure backend URL (if needed):**
   - The default backend URL is `http://localhost:5050`
   - To change it, create a `.env` file:
     ```
     VITE_API_BASE_URL=http://your-backend-url:port
     ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```

4. **Open your browser:**
   - Navigate to `http://localhost:5173`

## Usage

1. **Enter JIRA Ticket IDs:**
   - Type one or more ticket IDs (e.g., `ATA-36`, `ATA-13`)
   - Click "Add Ticket" to add more
   - Click "Generate Test Plan" to start generation

2. **View Results:**
   - **Test Plan Tab**: View all generated test cases organized by category
   - **RTM Tab**: View Requirement Traceability Matrix with coverage status

3. **Download:**
   - Click "Download RTM CSV" to export the traceability matrix
   - Click "Download Test Plan JSON" to export the test plan

## Troubleshooting

- **Backend connection errors**: Ensure the backend is running at the configured URL
- **Build errors**: Run `npm install` again to ensure all dependencies are installed
- **Port conflicts**: Change the port in `vite.config.ts` if port 5173 is in use

