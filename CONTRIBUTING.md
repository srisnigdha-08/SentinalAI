# Contributing to SentinelAI

Thank you for your interest in contributing to **SentinelAI**! We welcome contributions to improve our threat detection engine, deception mechanisms, real-time telemetry, and documentation.

## Code of Conduct

Please maintain a respectful, constructive, and collaborative environment. Be thoughtful when reviewing pull requests and reporting vulnerabilities responsibly.

## Development Environment Setup

Ensure you have the following prerequisites installed:
* **Node.js**: v24.x or latest LTS
* **Python**: v3.11.x
* **MongoDB Community Server**: v7.x or higher

### 1. Repository Setup
```bash
git clone https://github.com/srisnigdha-08/SentinalAI.git
cd SentinalAI
```

### 2. Backend Setup
```bash
cd backend
npm install
cp .env.example .env
# Edit .env with your local MongoDB URI and generated secret keys
npm run dev
```

### 3. AI Engine Setup
```bash
cd ../ai-engine
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# Ensure SENTINEL_KEY matches the backend .env
uvicorn inference.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Frontend Setup
```bash
cd ../frontend
npm install
cp .env.example .env
npm run dev
```

## Quality Standards & Testing

Before submitting a pull request, verify that all linters and test suites pass locally.

### Backend Tests & Linting
```bash
cd backend
npm run lint          # Run ESLint rules
npm run format        # Run Prettier code formatting
npm test              # Run Jest unit & integration tests
```

### AI Engine Tests
```bash
cd ai-engine
pytest                # Run full Pytest test suite
```

### Frontend Tests & Build
```bash
cd frontend
npm test              # Run frontend smoke and routing tests
npm run build         # Verify production bundle build passes
```

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
* `feat(scope)`: A new feature
* `fix(scope)`: A bug fix or security patch
* `docs(scope)`: Documentation updates
* `test(scope)`: Adding or updating test cases
* `refactor(scope)`: Code changes that neither fix a bug nor add a feature
* `chore(scope)`: Maintenance tasks, dependencies, build configs

## Pull Request Guidelines

1. Create a feature branch: `git checkout -b feature/your-feature-name`
2. Keep changes focused and atomic.
3. Include relevant unit/integration tests for any logic modifications.
4. Update relevant documentation or architecture diagrams if public interfaces change.
5. Submit your PR against the `main` branch with a clear description of the problem solved.
