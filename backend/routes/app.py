"""
SentinelGate / Zentry — Protected Demo Application Routes
=========================================================
Target application endpoints behind the Zentry Zero-Trust Security Gateway.
Demonstrates:
- Static fixture responses (no direct database queries)
- RBAC enforcement via Gateway Context and Auth dependencies
- Parameter reflection in /api/search?q= for WAF attack demonstration
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel

from backend.auth.dependencies import require_user
from backend.database.models import User
from backend.schemas.context import UserContext

router = APIRouter()


class MockUser(BaseModel):
    id: str
    name: str
    role: str
    department: str


class MockProduct(BaseModel):
    sku: str
    name: str
    price: float
    category: str
    status: str


class UsersResponse(BaseModel):
    source: str = "protected_demo_app"
    count: int
    users: list[MockUser]


class ProductsResponse(BaseModel):
    source: str = "protected_demo_app"
    count: int
    products: list[MockProduct]


class SearchResponse(BaseModel):
    source: str = "protected_demo_app"
    query: str
    total_matches: int
    results: list[dict[str, Any]]


class ProfileResponse(BaseModel):
    source: str = "protected_demo_app"
    user_id: str
    username: str
    role: str
    status: str


class DemoLoginRequest(BaseModel):
    username: str
    password: str


class DemoLoginResponse(BaseModel):
    source: str = "protected_demo_app"
    status: str
    message: str


# ── Static Fixture Data ───────────────────────────────────────────────────────

MOCK_USERS: list[MockUser] = [
    MockUser(id="usr_01", name="Elena Rostova", role="Security Engineer", department="SecOps"),
    MockUser(id="usr_02", name="Marcus Vance", role="Lead Architect", department="Core Platform"),
    MockUser(id="usr_03", name="Aria Chen", role="DevOps Engineer", department="Infrastructure"),
    MockUser(id="usr_04", name="Tariq Mansoor", role="Compliance Officer", department="Risk"),
]

MOCK_PRODUCTS: list[MockProduct] = [
    MockProduct(
        sku="ZNT-SENTRY-PRO",
        name="Zentry Gateway Pro Appliance",
        price=4999.00,
        category="Hardware Appliance",
        status="in_stock",
    ),
    MockProduct(
        sku="ZNT-AUDIT-HSM",
        name="Hardware Security Module (HSM) Cryptographic Key Vault",
        price=8900.00,
        category="Hardware Security",
        status="in_stock",
    ),
    MockProduct(
        sku="ZNT-SOC-ANALYTICS",
        name="Enterprise SOC Threat Intelligence License",
        price=12500.00,
        category="Enterprise Software",
        status="active",
    ),
]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get(
    "/users",
    response_model=UsersResponse,
    status_code=status.HTTP_200_OK,
    summary="List mock users (USER+ required)",
)
async def list_users(
    _user: User = Depends(require_user),
) -> UsersResponse:
    """Returns static mock user fixture from the protected application."""
    return UsersResponse(count=len(MOCK_USERS), users=MOCK_USERS)


@router.get(
    "/products",
    response_model=ProductsResponse,
    status_code=status.HTTP_200_OK,
    summary="List mock catalog products (USER+ required)",
)
async def list_products(
    _user: User = Depends(require_user),
) -> ProductsResponse:
    """Returns catalog products from the protected application."""
    return ProductsResponse(count=len(MOCK_PRODUCTS), products=MOCK_PRODUCTS)


@router.get(
    "/search",
    response_model=SearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Search protected products (USER+ required)",
)
async def search_products(
    q: str = Query(..., min_length=1, description="Search query string"),
    _user: User = Depends(require_user),
) -> SearchResponse:
    """
    Echoes query parameter 'q' in response to demonstrate gateway inspection.
    Malicious payloads (SQLi, XSS, Path Traversal) are blocked by the gateway
    before ever reaching this handler.
    """
    matched = [
        p.model_dump()
        for p in MOCK_PRODUCTS
        if q.lower() in p.name.lower() or q.lower() in p.sku.lower()
    ]
    return SearchResponse(
        query=q,
        total_matches=len(matched),
        results=matched,
    )


@router.get(
    "/profile",
    response_model=ProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user profile (USER+ required)",
)
async def get_profile(
    user: User = Depends(require_user),
) -> ProfileResponse:
    """Returns profile of currently authenticated user."""
    return ProfileResponse(
        user_id=user.id,
        username=user.username,
        role=user.role,
        status="active" if user.is_active else "inactive",
    )


@router.post(
    "/login",
    response_model=DemoLoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Demo application public login endpoint",
)
async def demo_login(
    body: DemoLoginRequest,
) -> DemoLoginResponse:
    """Public login simulation endpoint for protected application demo."""
    return DemoLoginResponse(
        status="success",
        message=f"Demo application received login for user '{body.username}'.",
    )
