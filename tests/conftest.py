"""Fixtures compartilhadas dos testes."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))

from diario.backends.local_backend import RepositorioLocal  # noqa: E402
from diario.service import DiarioService  # noqa: E402

PASSPHRASE_ALICE = "cafe-com-leite-42"
PASSPHRASE_BRUNO = "montanha-azul-77"


@pytest.fixture()
def repositorio(tmp_path: Path) -> RepositorioLocal:
    """Repositório local isolado, num banco descartável por teste."""
    repo = RepositorioLocal(tmp_path / "diario_teste.db")
    yield repo
    repo.fechar()


@pytest.fixture()
def servico(repositorio: RepositorioLocal) -> DiarioService:
    return DiarioService(repositorio)


@pytest.fixture()
def servico_com_alice(servico: DiarioService) -> DiarioService:
    """Alice logada, cofre criado e aberto, com uma nota escrita."""
    servico.criar_conta("alice@exemplo.test", "senha-da-conta")
    servico.criar_cofre(PASSPHRASE_ALICE)
    servico.criar_nota("Primeiro dia", "Hoje comecei a escrever um diário.")
    return servico


def entrar_como_bruno(servico: DiarioService) -> None:
    """Troca a sessão para um segundo usuário, com cofre próprio."""
    servico.sair()
    servico.criar_conta("bruno@exemplo.test", "senha-da-conta")
    servico.criar_cofre(PASSPHRASE_BRUNO)
