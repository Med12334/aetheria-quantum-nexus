package main

import (
"crypto/sha256"
"encoding/base64"
"strings"
)

// Layers 25 & 26: OAuth 2.1 PKCE (S256) + FIDO2/WebAuthn Hardware Token Authenticator
func VerifyOAuth21PkceAndFido2(codeVerifier string, expectedCodeChallenge string, fido2UserVerified bool, fido2HardwareBacked bool) bool {
if !fido2UserVerified || !fido2HardwareBacked || len(codeVerifier) < 43 {
return false
}
digest := sha256.Sum256([]byte(codeVerifier))
computedChallenge := base64.RawURLEncoding.EncodeToString(digest[:])
return computedChallenge == expectedCodeChallenge
}

// Layers 27 & 28: Active Directory / Entra ID Cross-Realm Trust & SCIMv2 Provisioning Guard
type CrossRealmPrincipal struct {
UserPrincipalName string
SourceRealm       string
TargetRealm       string
KerberosEncType   string
Scimv2Synced      bool
}

func AuthorizeCrossRealmAdTrust(p CrossRealmPrincipal) string {
if !p.Scimv2Synced {
return "DENY_SCIMV2_PROVISIONING_INCOMPLETE"
}
if p.KerberosEncType != "AES256-CTS-HMAC-SHA1-96" {
return "DENY_WEAK_KERBEROS_ENCTYPE"
}
if p.SourceRealm == "CORP.AETHERIA.INTERNAL" && p.TargetRealm == "HPC.AETHERIA.PREPROD" {
return "ALLOW_CROSS_REALM_KERBEROS_TRUST"
}
return "DENY_UNTRUSTED_REALM_BOUNDARY"
}

// Layers 29 & 30: FreeIPA / RHEL IdM / SSSD Host-Based Access Control (HBAC) & PKI mTLS Validator
type FreeIpaHbacRequest struct {
UnixUid           string
SssdGroup         string
TargetClusterHost string
ServiceName       string
ClientCertSan     string
CertRevokedOcsp   bool
}

func EvaluateFreeIpaHbacPolicy(req FreeIpaHbacRequest) bool {
if req.CertRevokedOcsp || !strings.HasSuffix(req.ClientCertSan, ".hpc.aetheria.preprod") {
return false
}
if strings.HasPrefix(req.TargetClusterHost, "xpu-preprod-") {
return req.SssdGroup == "ipa_cluster_sec_admins" || req.SssdGroup == "ipa_preprod_ir_team"
}
return false
}
