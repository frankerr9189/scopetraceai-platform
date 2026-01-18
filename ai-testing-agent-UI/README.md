# AI Testing Agent UI

A modern, futuristic dark-mode web UI for generating and viewing AI-powered test plans and requirement traceability matrices.

## Features

- **Multi-Ticket Input**: Enter one or more JIRA ticket IDs to generate comprehensive test plans
- **Test Plan Viewing**: View generated test cases organized by category (Happy Path, Data Validation, Authorization)
- **RTM Table**: View Requirement Traceability Matrix with coverage status
- **Export Functionality**: Download RTM as CSV and Test Plan as JSON
- **Dark, Futuristic UI**: Tesla/SpaceX/OpenAI-inspired aesthetic with glassmorphism and smooth animations

## Tech Stack

- **React 18** with TypeScript
- **Vite** for build tooling
- **Tailwind CSS** for styling
- **Framer Motion** for animations
- **Lucide React** for icons
- Custom UI components (shadcn/ui style)

## Getting Started

### Prerequisites

- Node.js 18+ and npm
- Backend API running at `http://localhost:5050`

### Installation

1. Install dependencies:
```bash
npm install
```

2. Configure the backend URL (optional):
   - Create a `.env` file with:
   ```
   VITE_API_BASE_URL=http://localhost:5050
   ```
   - Or modify `src/config.ts` directly

3. Start the development server:
```bash
npm run dev
```

4. Open your browser to `http://localhost:5173`

### Building for Production

```bash
npm run build
```

The built files will be in the `dist` directory.

## Project Structure

```
src/
├── components/          # React components
│   ├── ui/             # Base UI components (Button, Card, Badge, Tabs)
│   ├── Header.tsx      # App header
│   ├── TicketInputPanel.tsx  # Ticket input form
│   ├── TestPlanView.tsx      # Test plan display
│   └── RTMTable.tsx          # RTM table display
├── services/
│   └── api.ts          # API service layer
├── lib/
│   └── utils.ts        # Utility functions
├── config.ts           # Configuration
├── App.tsx             # Main app component
└── main.tsx            # Entry point
```

## API Integration

The UI communicates with the backend API at the following endpoints:

- `POST /generate-test-plan` - Generate test plan from JIRA tickets
- `GET /export/rtm` - Download RTM as CSV
- `GET /export/test-plan` - Download test plan as JSON

## Design Philosophy

- **Dark Mode Only**: Black/near-black backgrounds with subtle gradients
- **Glassmorphism**: Translucent cards with backdrop blur
- **Minimal Text**: High-contrast typography, no clutter
- **Smooth Animations**: Subtle transitions using Framer Motion
- **Audit-Ready**: Clear, readable displays for ISO compliance

## License

Private project - All rights reserved

