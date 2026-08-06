"""Diário Pessoal Criptografado — núcleo da aplicação.

Camadas (de baixo para cima):

* :mod:`diario.crypto`      — criptografia ponta a ponta (Scrypt + AES-256-GCM)
* :mod:`diario.models`      — modelos de domínio (nota cifrada × nota em claro)
* :mod:`diario.repository`  — contrato de persistência + fábrica de backend
* :mod:`diario.backends`    — Supabase (RLS real) e SQLite (modo demonstração)
* :mod:`diario.service`     — casos de uso, independentes de interface
"""

from .errors import (  # noqa: F401
    AcessoNegado,
    AutenticacaoError,
    BackendIndisponivel,
    CofreInexistente,
    CofreJaExiste,
    CriptografiaError,
    DiarioError,
    EnvelopeInvalido,
    PassphraseIncorreta,
    SessaoInexistente,
)
from .models import CofreRemoto, Nota, NotaCifrada, Sessao  # noqa: F401
from .repository import RepositorioDiario, criar_repositorio  # noqa: F401
from .service import DiarioService  # noqa: F401

__version__ = "1.0.0"

__all__ = [
    "AcessoNegado",
    "AutenticacaoError",
    "BackendIndisponivel",
    "CofreInexistente",
    "CofreJaExiste",
    "CofreRemoto",
    "CriptografiaError",
    "DiarioError",
    "DiarioService",
    "EnvelopeInvalido",
    "Nota",
    "NotaCifrada",
    "PassphraseIncorreta",
    "RepositorioDiario",
    "Sessao",
    "SessaoInexistente",
    "criar_repositorio",
]
