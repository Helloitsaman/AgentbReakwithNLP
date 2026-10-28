"""
FastAPI router providing all `/api/*` endpoints required by the
AgentBreak Security Evaluation Dashboard frontend.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app import platform_store

router = APIRouter(prefix="/api", tags=["AgentBreak Platform API"])


class ExecutionModeRequest(BaseModel):
    execution_mode: str = "deterministic"
    llm_provider: str = "ollama"
    llm_model: str = "google/gemini-2.5-flash-lite"
    ollama_base_url: str = "http://localhost:11434"


class PolicyUpdateRequest(BaseModel):
    policy_config: dict[str, Any]


class StartTestRunRequest(BaseModel):
    agent_id: str
    name: str
    scenario_codes: list[str] | None = None
    categories: list[str] | None = None
    include_benign_baseline: bool = True
    enable_adaptive_followups: bool = True
    execution_mode: str = "deterministic"
    max_steps: int = 16
    time_budget_seconds: int = 60
    llm_config: dict[str, Any] | None = None


class FindingStatusRequest(BaseModel):
    status: Literal["Open", "Reproduced", "Mitigated", "Accepted"]


class ExecuteReplayRequest(BaseModel):
    original_run_id: str
    apply_defenses: dict[str, bool]
    update_agent_policy_permanently: bool = False


@router.get("/system/status")
def get_system_status():
    return platform_store.get_system_status()


@router.post("/system/execution-mode")
def update_execution_mode(req: ExecutionModeRequest):
    return platform_store.update_execution_mode(req.model_dump())


@router.post("/system/reset-demo")
def reset_demo_workspace():
    return platform_store.reset_workspace_runs()


@router.get("/agents")
def list_agents():
    return platform_store.list_agents()


@router.patch("/agents/{agent_id}/policy")
def update_agent_policy(agent_id: str, req: PolicyUpdateRequest):
    updated = platform_store.update_agent_policy(agent_id, req.policy_config)
    if not updated:
        raise HTTPException(status_code=404, detail="Agent not found")
    return updated


@router.post("/agents/{agent_id}/preset/{preset}")
def apply_policy_preset(agent_id: str, preset: Literal["unprotected", "hardened"]):
    updated = platform_store.apply_agent_preset(agent_id, preset)
    if not updated:
        raise HTTPException(status_code=404, detail="Agent not found")
    return updated


@router.get("/scenarios")
def list_scenarios():
    return platform_store.list_scenarios()


@router.get("/test-runs")
def list_test_runs():
    return platform_store.list_test_runs()


@router.post("/test-runs")
def start_test_run(req: StartTestRunRequest):
    return platform_store.start_test_run(req.model_dump())


@router.get("/test-runs/{run_id}")
def get_test_run_details(run_id: str):
    details = platform_store.get_test_run_details(run_id)
    if not details:
        raise HTTPException(status_code=404, detail="Test run not found")
    return details


@router.get("/test-runs/{run_id}/traces")
def get_test_run_traces(run_id: str, test_case_id: str | None = Query(default=None)):
    traces = platform_store.get_test_run_traces(run_id, test_case_id)
    if not traces:
        raise HTTPException(status_code=404, detail="Test run not found")
    return traces


@router.get("/findings")
def list_findings(run_id: str | None = Query(default=None)):
    return platform_store.list_findings(run_id)


@router.patch("/findings/{finding_id}")
def update_finding_status(finding_id: str, req: FindingStatusRequest):
    updated = platform_store.update_finding_status(finding_id, req.status)
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")
    return updated


@router.get("/replays")
def list_replays(original_run_id: str | None = Query(default=None)):
    return platform_store.list_replays(original_run_id)


@router.post("/replays")
def execute_replay(req: ExecuteReplayRequest):
    replay = platform_store.execute_replay(req.model_dump())
    if not replay:
        raise HTTPException(status_code=404, detail="Original test run not found")
    return replay


@router.get("/reports/{run_id}")
def get_report(run_id: str):
    report = platform_store.build_report(run_id)
    if not report:
        raise HTTPException(status_code=404, detail="Test run not found")
    return report
