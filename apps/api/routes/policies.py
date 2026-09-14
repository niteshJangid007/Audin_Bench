"""
Security Policies API Route.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from database.session import get_db
from database.models import SecurityPolicy, Organization
from engine.models import SecurityPolicyDefinition

router = APIRouter()


class CreatePolicyRequest(BaseModel):
    name: str
    repository_id: Optional[str] = None
    definition: SecurityPolicyDefinition


class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = None
    definition: Optional[SecurityPolicyDefinition] = None
    is_active: Optional[bool] = None


@router.get("/policies")
def list_policies(
    repository_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(SecurityPolicy).filter_by(is_active=True)
    if repository_id:
        query = query.filter(
            (SecurityPolicy.repository_id == repository_id) | (SecurityPolicy.repository_id.is_(None))
        )
    policies = query.all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "organization_id": p.organization_id,
            "repository_id": p.repository_id,
            "definition": p.definition,
            "is_active": p.is_active,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        }
        for p in policies
    ]


@router.post("/policies", status_code=201)
def create_policy(req: CreatePolicyRequest, db: Session = Depends(get_db)):
    org = db.query(Organization).first()
    if not org:
        raise HTTPException(status_code=400, detail="No organization configured")

    new_policy = SecurityPolicy(
        organization_id=org.id,
        repository_id=req.repository_id,
        name=req.name,
        definition=req.definition.model_dump(),
        is_active=True,
    )
    db.add(new_policy)
    db.commit()
    db.refresh(new_policy)

    return {"id": new_policy.id, "name": new_policy.name, "status": "created"}


@router.put("/policies/{policy_id}")
def update_policy(policy_id: str, req: UpdatePolicyRequest, db: Session = Depends(get_db)):
    policy = db.query(SecurityPolicy).filter_by(id=policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    if req.name is not None:
        policy.name = req.name
    if req.definition is not None:
        policy.definition = req.definition.model_dump()
    if req.is_active is not None:
        policy.is_active = req.is_active

    db.commit()
    return {"id": policy.id, "name": policy.name, "status": "updated"}
