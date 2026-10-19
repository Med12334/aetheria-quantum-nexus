from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, List
from nexus_ai.autonomous_defense import AutonomousAiSandboxGuard, ClusterIncidentResponseOrchestrator

app = FastAPI(title="Aetheria-Quantum-Nexus AI Sandbox & Cluster Incident Response API", version="1.0.0")
guard = AutonomousAiSandboxGuard()
ir_orchestrator = ClusterIncidentResponseOrchestrator()

class AgentActionRequest(BaseModel):
    agent_id: str
    tool_command: str
    sandbox_profile: Dict[str, bool]
    egress_bytes_mb: float

class IncidentRequest(BaseModel):
    node_id: str
    telemetry_alerts: List[str]

@app.get("/health")
def health():
    return {"status": "UP", "layers": "L18-L24-Autonomous-AI-Sandbox-And-Cluster-IR-DR"}

@app.post("/api/v1/sandbox/evaluate")
def evaluate_agent(req: AgentActionRequest):
    return guard.evaluate_agent_action(
        req.agent_id, req.tool_command, req.sandbox_profile, req.egress_bytes_mb
    )

@app.post("/api/v1/incident/respond")
def respond_incident(req: IncidentRequest):
    return ir_orchestrator.execute_ir_dr_playbook(req.node_id, req.telemetry_alerts)
