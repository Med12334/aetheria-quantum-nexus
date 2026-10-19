from typing import Dict, Any, List

class AutonomousAiSandboxGuard:
    """
    Layers 18-21: Securing Autonomous AI Agents via Sandboxing and Behavioral Threat Detection.
    Prevents indirect prompt injection, autonomous lateral movement, BMC tampering, and weight exfiltration.
    """

    FORBIDDEN_SYSCALL_PATTERNS = (
        "ipmitool",
        "bmc_reset",
        "firmware_flash",
        "opensm_pkey_override",
        "curl http://169.254.169.254",
        "/dev/mem",
        "insmod"
    )

    def evaluate_agent_action(
        self,
        agent_id: str,
        tool_command: str,
        sandbox_profile: Dict[str, bool],
        egress_bytes_mb: float
    ) -> Dict[str, Any]:
        cmd_lower = tool_command.lower()

        if not (
            sandbox_profile.get("seccomp_bpf_active", False)
            and sandbox_profile.get("unprivileged_userns", False)
            and sandbox_profile.get("readonly_rootfs", False)
        ):
            return {
                "agent_id": agent_id,
                "verdict": "BLOCK_UNSANDBOXED_AI_AGENT",
                "threat_score": 98.0,
                "reason": "AI Agent missing mandatory Seccomp-BPF, UserNS, or Read-Only RootFS sandbox controls."
            }

        for pattern in self.FORBIDDEN_SYSCALL_PATTERNS:
            if pattern in cmd_lower:
                return {
                    "agent_id": agent_id,
                    "verdict": "QUARANTINE_AGENT_PROMPT_INJECTION_DETECTED",
                    "threat_score": 99.5,
                    "matched_signature": pattern,
                    "reason": f"Autonomous defense blocked unauthorized hardware/cluster command: {pattern}"
                }

        if egress_bytes_mb > 500.0:
            return {
                "agent_id": agent_id,
                "verdict": "BLOCK_WEIGHT_EXFILTRATION_ANOMALY",
                "threat_score": 93.0,
                "reason": "Anomalous high-volume outbound transfer from sandboxed AI agent."
            }

        return {
            "agent_id": agent_id,
            "verdict": "ALLOW_SANDBOXED_TOOL_CALL",
            "threat_score": 3.5,
            "reason": "Nominal sandboxed AI agent execution."
        }


class ClusterIncidentResponseOrchestrator:
    """
    Layers 22-24: Pre-Production Cluster Incident Response (IR), Disaster Recovery (DR),
    and Automated Root-Cause Analysis (RCA) with Executive Risk Reporting.
    """

    def execute_ir_dr_playbook(self, node_id: str, telemetry_alerts: List[str]) -> Dict[str, Any]:
        combined = " ".join(telemetry_alerts).upper()
        containment_actions: List[str] = []
        root_cause = "Unclassified telemetry anomaly"
        executive_risk_tier = "MODERATE"

        if "PKEY_MISMATCH" in combined or "UNAUTHORIZED_RDMA" in combined:
            root_cause = "Cross-tenant InfiniBand RDMA queue-pair isolation breach attempt"
            executive_risk_tier = "CRITICAL_SEV1"
            containment_actions = [
                f"Revoke InfiniBand P_Key membership on {node_id} via Subnet Manager M_Key control plane",
                f"Drain Slurm compute partition on {node_id} and scrub HBM3e accelerator VRAM",
                "Rotate FreeIPA host mTLS certificates and trigger DR golden image re-attestation"
            ]
        elif "FIRMWARE_DIGEST_DRIFT" in combined or "SPDM_FAIL" in combined:
            root_cause = "Pre-production compute tray SPDM firmware measurement drift or unauthorized flash"
            executive_risk_tier = "CRITICAL_SEV1"
            containment_actions = [
                f"Isolate {node_id} BMC VRF and trigger hardware Root-of-Trust golden firmware rollback",
                "Preserve eBPF ring-buffer forensic audit snapshot in tamper-evident Merkle vault"
            ]

        return {
            "affected_cluster_node": node_id,
            "executive_risk_tier": executive_risk_tier,
            "root_cause_analysis": root_cause,
            "automated_dr_containment_steps": containment_actions,
            "rto_recovery_target_minutes": 6
        }
