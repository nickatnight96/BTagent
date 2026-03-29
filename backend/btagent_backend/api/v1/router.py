"""API v1 router — mounts all sub-routers."""

from fastapi import APIRouter

from btagent_backend.api.v1.auth import router as auth_router
from btagent_backend.api.v1.config import router as config_router
from btagent_backend.api.v1.health import router as health_router
from btagent_backend.api.v1.investigations import router as investigations_router
from btagent_backend.api.v1.iocs import router as iocs_router
from btagent_backend.api.v1.knowledge import router as knowledge_router
from btagent_backend.api.v1.mitre import router as mitre_router
from btagent_backend.api.v1.playbooks import router as playbooks_router
from btagent_backend.api.v1.reports import router as reports_router
from btagent_backend.api.v1.webhooks import router as webhooks_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_router)
api_v1_router.include_router(config_router)
api_v1_router.include_router(investigations_router)
api_v1_router.include_router(iocs_router)
api_v1_router.include_router(knowledge_router)
api_v1_router.include_router(mitre_router)
api_v1_router.include_router(playbooks_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(webhooks_router)

# Health at root level (no /api/v1 prefix)
health_router_root = health_router
