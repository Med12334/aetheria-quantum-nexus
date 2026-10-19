//! Aetheria-Quantum-Nexus Layers 11 to 17 (Memory-Safe Rust Security):
//! - Layer 11 & 12: Post-Quantum ML-KEM / Lattice Polynomial Commitment Verifier
//! - Layer 13 & 14: InfiniBand Partition Key (P_Key) & Subnet Manager Management Key (M_Key) Enforcer
//! - Layer 15 & 16: Enroot / Docker / Kubernetes Unprivileged Container Isolation Validator
//! - Layer 17: Zero-Trust VRF & VLAN Micro-Segmentation Firewall

#[derive(Debug, Clone, PartialEq)]
pub enum FabricSecurityDecision {
    AllowRdmaChannel,
    DenyDefaultPartitionKey,
    DenyInvalidSubnetMKey,
    DenyCrossTenantPKeyViolation,
}

#[derive(Debug, Clone)]
pub struct InfiniBandFrame {
    pub assigned_tenant_pkey: u16,
    pub packet_pkey: u16,
    pub provided_mkey: u64,
    pub expected_mkey: u64,
    pub is_subnet_management_mad: bool,
}

/// Layers 11 & 12: Post-Quantum Lattice Modular Norm Bound Check (ML-KEM / Dilithium style)
pub fn verify_post_quantum_lattice_norm(polynomial_coeffs: &[i32], modulus_q: i32, beta_bound: i32) -> bool {
    if polynomial_coeffs.is_empty() || modulus_q <= 0 {
        return false;
    }
    polynomial_coeffs.iter().all(|&c| c.abs() <= beta_bound && c.abs() < modulus_q)
}

/// Layers 13 & 14: InfiniBand P_Key & M_Key High-Speed Fabric Enforcer
pub fn evaluate_infiniband_frame(frame: &InfiniBandFrame) -> FabricSecurityDecision {
    if frame.packet_pkey == 0x7FFF || frame.packet_pkey == 0xFFFF {
        return FabricSecurityDecision::DenyDefaultPartitionKey;
    }
    if frame.is_subnet_management_mad && frame.provided_mkey != frame.expected_mkey {
        return FabricSecurityDecision::DenyInvalidSubnetMKey;
    }
    if (frame.assigned_tenant_pkey & 0x7FFF) != (frame.packet_pkey & 0x7FFF) {
        return FabricSecurityDecision::DenyCrossTenantPKeyViolation;
    }
    FabricSecurityDecision::AllowRdmaChannel
}

/// Layers 15 & 16: Enroot / Docker / Kubernetes Container Workload Security Policy
#[derive(Debug, Clone)]
pub struct ContainerSecurityProfile {
    pub runtime_name: String,
    pub rootless_userns: bool,
    pub no_new_privileges: bool,
    pub host_network_shared: bool,
    pub scoped_accelerator_ids: Vec<String>,
}

pub fn verify_container_hardening(profile: &ContainerSecurityProfile) -> Result<&'static str, &'static str> {
    if !profile.rootless_userns {
        return Err("VIOLATION_ROOT_USERNS_FORBIDDEN");
    }
    if !profile.no_new_privileges {
        return Err("VIOLATION_MISSING_NO_NEW_PRIVS");
    }
    if profile.host_network_shared {
        return Err("VIOLATION_HOST_NETWORK_EXPOSED");
    }
    if profile.scoped_accelerator_ids.is_empty() || profile.scoped_accelerator_ids.iter().any(|id| id == "ALL") {
        return Err("VIOLATION_UNSCOPED_ACCELERATOR_MOUNT");
    }
    Ok("CONTAINER_SANDBOX_HARDENED_OK")
}

/// Layer 17: Zero-Trust VRF & VLAN Micro-Segmentation Verifier
pub fn verify_zero_trust_vrf_vlan(src_vrf: &str, dst_vrf: &str, vlan_tag: u16, dst_port: u16) -> bool {
    if vlan_tag <= 1 || vlan_tag > 4094 {
        return false;
    }
    if src_vrf == dst_vrf {
        return true;
    }
    dst_vrf == "VRF_ZERO_TRUST_IDENTITY_HUB" && dst_port == 443
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_post_quantum_lattice_norm_bound() {
        let valid_poly = [120, -340, 88, 412, -19];
        assert!(verify_post_quantum_lattice_norm(&valid_poly, 8380417, 500));

        let forged_poly = [120, 99999, 88];
        assert!(!verify_post_quantum_lattice_norm(&forged_poly, 8380417, 500));
    }

    #[test]
    fn test_infiniband_pkey_and_mkey_protection() {
        let valid = InfiniBandFrame {
            assigned_tenant_pkey: 0x8201,
            packet_pkey: 0x8201,
            provided_mkey: 0xABCDEF0123456789,
            expected_mkey: 0xABCDEF0123456789,
            is_subnet_management_mad: true,
        };
        assert_eq!(evaluate_infiniband_frame(&valid), FabricSecurityDecision::AllowRdmaChannel);

        let default_partition_attack = InfiniBandFrame {
            assigned_tenant_pkey: 0x8201,
            packet_pkey: 0x7FFF,
            provided_mkey: 0,
            expected_mkey: 0xABCDEF0123456789,
            is_subnet_management_mad: false,
        };
        assert_eq!(
            evaluate_infiniband_frame(&default_partition_attack),
            FabricSecurityDecision::DenyDefaultPartitionKey
        );
    }

    #[test]
    fn test_enroot_container_and_vrf_vlan_enforcement() {
        let enroot = ContainerSecurityProfile {
            runtime_name: String::from("enroot"),
            rootless_userns: true,
            no_new_privileges: true,
            host_network_shared: false,
            scoped_accelerator_ids: vec![String::from("XPU-UUID-001")],
        };
        assert_eq!(verify_container_hardening(&enroot), Ok("CONTAINER_SANDBOX_HARDENED_OK"));
        assert!(verify_zero_trust_vrf_vlan("VRF_RESEARCH_A", "VRF_RESEARCH_A", 310, 29500));
        assert!(!verify_zero_trust_vrf_vlan("VRF_RESEARCH_A", "VRF_RESEARCH_B", 310, 22));
    }
}
