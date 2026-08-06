"""Modelos de domínio do diário.

Distinção que atravessa o projeto inteiro:

* :class:`NotaCifrada` é o que existe **no banco** — título e conteúdo opacos.
* :class:`Nota` é o que existe **na tela** — texto em claro, só na memória do
  cliente e apenas enquanto o cofre estiver aberto.

Manter os dois tipos separados evita o acidente mais caro possível neste
projeto: mandar texto em claro para o banco por engano.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Sessao:
    """Sessão autenticada de um usuário."""

    user_id: str
    email: str
    access_token: str | None = None
    refresh_token: str | None = None


@dataclass(frozen=True)
class NotaCifrada:
    """Uma linha de ``public.notes``, exatamente como o servidor a enxerga."""

    id: str
    user_id: str
    title_cipher: str
    content_cipher: str
    created_at: datetime
    updated_at: datetime
    crypto_version: int = 1

    @classmethod
    def de_dict(cls, dados: dict[str, Any]) -> "NotaCifrada":
        """Constrói a partir do JSON devolvido pelo PostgREST/SQLite."""
        return cls(
            id=str(dados["id"]),
            user_id=str(dados["user_id"]),
            title_cipher=dados["title_cipher"],
            content_cipher=dados["content_cipher"],
            created_at=_para_datetime(dados["created_at"]),
            updated_at=_para_datetime(dados["updated_at"]),
            crypto_version=int(dados.get("crypto_version", 1)),
        )


@dataclass(frozen=True)
class Nota:
    """Uma nota já decifrada, pronta para exibição."""

    id: str
    titulo: str
    conteudo: str
    created_at: datetime
    updated_at: datetime

    @property
    def resumo(self) -> str:
        """Primeira linha do conteúdo, truncada — usada na listagem lateral."""
        primeira_linha = self.conteudo.strip().splitlines()[0] if self.conteudo.strip() else ""
        return primeira_linha[:80] + ("…" if len(primeira_linha) > 80 else "")


@dataclass(frozen=True)
class CofreRemoto:
    """Uma linha de ``public.diary_keys``."""

    user_id: str
    kdf_salt: str
    wrapped_dek: str
    kdf_params: dict[str, Any]
    crypto_version: int = 1

    @classmethod
    def de_dict(cls, dados: dict[str, Any]) -> "CofreRemoto":
        params = dados.get("kdf_params") or {}
        if isinstance(params, str):  # SQLite guarda jsonb como texto
            import json

            params = json.loads(params)
        return cls(
            user_id=str(dados["user_id"]),
            kdf_salt=dados["kdf_salt"],
            wrapped_dek=dados["wrapped_dek"],
            kdf_params=params,
            crypto_version=int(dados.get("crypto_version", 1)),
        )


def _para_datetime(valor: Any) -> datetime:
    """Normaliza timestamps vindos do PostgREST (ISO 8601) ou do SQLite."""
    if isinstance(valor, datetime):
        return valor
    texto = str(valor)
    # PostgREST devolve "2026-07-31T12:00:00.123456+00:00"; o Python 3.11+ já
    # entende esse formato, mas o sufixo "Z" continua fora do padrão aceito.
    if texto.endswith("Z"):
        texto = texto[:-1] + "+00:00"
    return datetime.fromisoformat(texto)
