"""Router assembly.

The same routers are mounted twice: /api/v1 (canonical — new clients) and
/api (legacy, deprecated; kept until every released client defaults to the
versioned base path). Both mounts share the rate-limit buckets — the bucket
names ride the dependencies, so a client cannot double its allowance by
alternating mounts.
"""

from fastapi import APIRouter

from . import account, auth, consents, entries, insights, measures, meta, therapist

_module_routers = (
    auth.router,
    entries.router,
    measures.router,
    insights.router,
    account.router,
    consents.router,
    therapist.router,
    meta.router,
)

# Canonical, versioned mount.
api_v1_router = APIRouter(prefix="/api/v1")
for _router in _module_routers:
    api_v1_router.include_router(_router)

# Deprecated unversioned mount (see module docstring).
api_router = APIRouter(prefix="/api")
for _router in _module_routers:
    api_router.include_router(_router)
