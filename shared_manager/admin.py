"""Authenticated, read-only administrator views of account and profile counts."""
from __future__ import annotations

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from .store import Store


class AdminSummary(BaseModel):
    registeredUsers: int
    enabledUsers: int
    totalConnections: int
    readyConnections: int
    pendingConnections: int
    deletingConnections: int


class AdminUser(BaseModel):
    username: str
    createdAt: str
    enabled: bool
    isAdmin: bool
    totalConnections: int
    readyConnections: int
    pendingConnections: int
    deletingConnections: int


class AdminUsersView(BaseModel):
    summary: AdminSummary
    items: list[AdminUser]
    total: int
    page: int
    pageSize: int
    totalPages: int


def create_admin_router(current_user: Callable, store: Store) -> APIRouter:
    """Expose only account metadata after checking the current durable role."""
    router = APIRouter(prefix="/api/admin", tags=["管理员"])

    def administrator(user=Depends(current_user)):
        if not user.get("is_admin"):
            raise HTTPException(403, "仅管理员可查看用户统计")
        return user

    @router.get("/users", response_model=AdminUsersView)
    def users(search: str = Query(default="", max_length=64),
              page: int = Query(default=1, ge=1, le=1000000),
              page_size: int = Query(default=20, ge=1, le=100, alias="pageSize"),
              _user=Depends(administrator)):
        return store.admin_users(search=search, page=page, page_size=page_size)

    return router
