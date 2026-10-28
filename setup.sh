#!/usr/bin/env bash
# One-shot setup for AgentBreak + NLP (backend deps + model, then frontend deps).
set -e
cd "$(dirname "$0")"
echo "==> Backend: installing Python dependencies"
cd backend
python3 -m pip install -r requirements.txt
echo "==> Backend: ensuring the injection classifier is trained"
python3 -m nlp.injection_clf --train || echo "(model already present)"
[ -f .env ] || cp .env.example .env
cd ..
echo "==> Frontend: installing Node dependencies"
cd frontend && npm install
echo
echo "Done. Run the backend:  cd backend && python3 main.py"
echo "Run the frontend:        cd frontend && npm run dev   (http://localhost:5174)"
