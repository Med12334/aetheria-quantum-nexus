from nexus_ai.autonomous_defense import AutonomousAiSandboxGuard, ClusterIncidentResponseOrchestrator

def test_sandbox_blocks_prompt_injected_firmware_command():
    guard = AutonomousAiSandboxGuard()
    strict_sandbox = {
        "seccomp_bpf_active": True,
        "unprivileged_userns": True,
        "readonly_rootfs": True
    }

    malicious = guard.evaluate_agent_action(
        "agent-alpha-01",
        "firmware_flash --target=0 rogue_image.rom",
        strict_sandbox,
        egress_bytes_mb=1.0
    )
    assert malicious["verdict"] == "QUARANTINE_AGENT_PROMPT_INJECTION_DETECTED"
    assert malicious["threat_score"] >= 99.0

    benign = guard.evaluate_agent_action(
        "agent-alpha-01",
        "pytest tests/test_distributed_training.py",
        strict_sandbox,
        egress_bytes_mb=2.0
    )
    assert benign["verdict"] == "ALLOW_SANDBOXED_TOOL_CALL"

def test_incident_response_playbook_isolates_rdma_breach():
    ir = ClusterIncidentResponseOrchestrator()
    report = ir.execute_ir_dr_playbook(
        "xpu-supercluster-rack02-node07",
        ["IB_ALERT: PKEY_MISMATCH on mlx5_0", "UNAUTHORIZED_RDMA write attempt"]
    )
    assert report["executive_risk_tier"] == "CRITICAL_SEV1"
    assert len(report["automated_dr_containment_steps"]) == 3
    assert report["rto_recovery_target_minutes"] <= 10
