"""Adapter shartnomasi.

Har bir "gunoh" — bu tashqi tool'ning yupqa adapter'i.
Adapter faqat 3 ta narsa qiladi:
  1. tool bor-yo'qligini tekshiradi
  2. tool'ni ishga tushiradi
  3. chiqishni FindingContract ga aylantiradi

Hech qanday payload, hech qanday exploit logikasi bu yerda yozilmaydi —
hammasi tayyor tool'larning ichida.
"""

from __future__ import annotations

from typing import ClassVar, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from ..schemas import Category, FindingContract


class ScanContext(BaseModel):
    target: str
    max_rps: int = 50
    timeout: int = 900
    templates: list[str] = Field(default_factory=list)
    # `info` sukut bo'yicha chiqarilmaydi — shovqin ko'p (masalan security header'lar)
    severities: list[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])


@runtime_checkable
class Adapter(Protocol):
    name: ClassVar[str]
    category: ClassVar[Category]
    sin: ClassVar[str]  # ichki kod nomi

    def available(self) -> bool: ...

    def run(self, ctx: ScanContext) -> list[FindingContract]: ...
