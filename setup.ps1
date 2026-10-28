# One-shot setup for AgentBreak + NLP on Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
Write-Host "==> Backend: installing Python dependencies"
Set-Location backend
python -m pip install -r requirements.txt
Write-Host "==> Backend: training the injection classifier"
python -m nlp.injection_clf --train
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
Set-Location ..
Write-Host "==> Frontend: installing Node dependencies"
Set-Location frontend; npm install; Set-Location ..
Write-Host ""
Write-Host "Done. Backend:  cd backend; python main.py"
Write-Host "Frontend:       cd frontend; npm run dev   (http://localhost:5174)"
