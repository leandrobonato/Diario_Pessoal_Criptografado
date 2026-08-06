"""Configuração da aplicação, lida de variáveis de ambiente / arquivo ``.env``.

Regra inegociável: **nenhuma chave entra no código**. O arquivo ``.env`` está
no ``.gitignore``; o que é versionado é o ``.env.example``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:  # python-dotenv é conveniência, não obrigação
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    def load_dotenv(*_args, **_kwargs):  # type: ignore[misc]
        return False


#: Raiz do projeto (…/Diario_Pessoal_Criptografado)
RAIZ_PROJETO = Path(__file__).resolve().parents[2]

#: Onde ficam os artefatos gerados localmente (banco demo, exportações).
PASTA_DADOS = RAIZ_PROJETO / "data"


@dataclass(frozen=True)
class Configuracao:
    """Configuração efetiva da execução atual."""

    backend: str          # "supabase" | "local"
    supabase_url: str
    supabase_anon_key: str
    caminho_banco_demo: Path

    @property
    def usa_supabase(self) -> bool:
        return self.backend == "supabase"

    @property
    def supabase_configurado(self) -> bool:
        return bool(self.supabase_url and self.supabase_anon_key)


def carregar_configuracao() -> Configuracao:
    """Lê o ``.env`` (se existir) e resolve o backend a ser usado.

    ``DIARIO_BACKEND`` aceita:

    * ``auto`` (padrão) — usa o Supabase se houver URL e chave; senão cai no
      modo demonstração local. É o que faz o projeto rodar em qualquer máquina
      recém-clonada, sem cadastro nenhum.
    * ``supabase`` — exige as credenciais; falha alto se faltarem.
    * ``local`` — força o modo demonstração mesmo com credenciais presentes.
    """
    load_dotenv(RAIZ_PROJETO / ".env")

    url = os.getenv("SUPABASE_URL", "").strip()
    anon_key = os.getenv("SUPABASE_ANON_KEY", "").strip()
    escolhido = os.getenv("DIARIO_BACKEND", "auto").strip().lower()

    if escolhido == "auto":
        backend = "supabase" if (url and anon_key) else "local"
    elif escolhido in {"supabase", "local"}:
        backend = escolhido
    else:
        raise ValueError(
            f"DIARIO_BACKEND inválido: {escolhido!r}. Use 'auto', 'supabase' ou 'local'."
        )

    caminho_banco = Path(
        os.getenv("DIARIO_DB_PATH", str(PASTA_DADOS / "diario_demo.db"))
    )

    return Configuracao(
        backend=backend,
        supabase_url=url,
        supabase_anon_key=anon_key,
        caminho_banco_demo=caminho_banco,
    )


def alerta_de_chave_de_servico() -> str | None:
    """Detecta a presença da ``service_role`` key no ambiente do cliente.

    A service_role key tem ``BYPASSRLS``: ela ignora todas as policies. Se
    alguém a colocar no ambiente do app por engano, todo o isolamento deste
    projeto vira decoração. Detectar e gritar é mais barato do que descobrir
    depois.
    """
    suspeitas = [
        nome
        for nome in os.environ
        if "SERVICE_ROLE" in nome.upper() or "SERVICE_KEY" in nome.upper()
    ]
    if suspeitas:
        return (
            "Chave de serviço detectada no ambiente ("
            + ", ".join(sorted(suspeitas))
            + "). O app do usuário deve usar SOMENTE a anon key — "
            "a service_role ignora o RLS."
        )
    return None
