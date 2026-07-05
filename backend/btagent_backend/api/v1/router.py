"""API v1 router — mounts all sub-routers."""

from fastapi import APIRouter

from btagent_backend.api.v1.audit import router as audit_router
from btagent_backend.api.v1.auth import router as auth_router
from btagent_backend.api.v1.behavioral import router as behavioral_router
from btagent_backend.api.v1.config import router as config_router
from btagent_backend.api.v1.cti_detection import router as cti_detection_router
from btagent_backend.api.v1.health import router as health_router
from btagent_backend.api.v1.hunt_findings import router as hunt_router
from btagent_backend.api.v1.hunts import router as hunts_router
from btagent_backend.api.v1.identity import router as identity_router
from btagent_backend.api.v1.investigations import router as investigations_router
from btagent_backend.api.v1.iocs import router as iocs_router
from btagent_backend.api.v1.knowledge import router as knowledge_router
from btagent_backend.api.v1.mfa import router as mfa_router
from btagent_backend.api.v1.mitigation import router as mitigation_router
from btagent_backend.api.v1.mitre import router as mitre_router
from btagent_backend.api.v1.pattern_hunt import router as pattern_hunt_router
from btagent_backend.api.v1.playbooks import router as playbooks_router
from btagent_backend.api.v1.reports import router as reports_router
from btagent_backend.api.v1.response_plan import router as response_plan_router
from btagent_backend.api.v1.saml import router as saml_router
from btagent_backend.api.v1.sso import router as sso_router
from btagent_backend.api.v1.tlp_policies import router as tlp_policies_router
from btagent_backend.api.v1.triage import router as triage_router
from btagent_backend.api.v1.webhooks import router as webhooks_router
from btagent_backend.api.v1.workflows import router as workflows_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(audit_router)
api_v1_router.include_router(auth_router)
api_v1_router.include_router(config_router)
api_v1_router.include_router(hunt_router)
api_v1_router.include_router(hunts_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(iocs_router)
api_v1_router.include_router(knowledge_router)
api_v1_router.include_router(mfa_router)
api_v1_router.include_router(mitigation_router)
api_v1_router.include_router(mitre_router)
api_v1_router.include_router(playbooks_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(response_plan_router)
api_v1_router.include_router(saml_router)
api_v1_router.include_router(sso_router)
api_v1_router.include_router(tlp_policies_router)
api_v1_router.include_router(triage_router)
api_v1_router.include_router(webhooks_router)
api_v1_router.include_router(workflows_router)
api_v1_router.include_router(behavioral_router)
api_v1_router.include_router(cti_detection_router)
api_v1_router.include_router(identity_router)
api_v1_router.include_router(pattern_hunt_router)

# Health at root level (no /api/v1 prefix)
health_router_root = health_router
