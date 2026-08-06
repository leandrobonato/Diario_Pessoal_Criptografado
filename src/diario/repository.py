"""Contrato de persistência do diário.

Existem duas implementações:

* :mod:`diario.backends.supabase_backend` — o alvo real: Supabase Auth +
  PostgREST, com o isolamento garantido pelas policies de RLS no Postgres.
* :mod:`diario.backends.local_backend` — modo demonstração em SQLite, que
  reproduz as mesmas regras na camada de aplicação para que o projeto rode
  sem nenhuma conta na nuvem.

O app fala **só** com este contrato. Trocar de backend é trocar uma variável
de ambiente — nenhuma linha da UI muda.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .crypto import MaterialDoCofre
from .models import CofreRemoto, NotaCifrada, Sessao


@runtime_checkable
class RepositorioDiario(Protocol):
    """Operações que o diário precisa da camada de dados."""

    #: Rótulo exibido na interface ("Supabase" / "Demonstração local").
    nome: str

    # -- autenticação ------------------------------------------------------ #
    @property
    def sessao(self) -> Sessao | None:
        """Sessão ativa, ou ``None`` se ninguém estiver logado."""

    def criar_conta(self, email: str, senha: str) -> Sessao:
        """Cadastra um usuário e já devolve a sessão autenticada."""

    def entrar(self, email: str, senha: str) -> Sessao:
        """Autentica e abre uma sessão."""

    def sair(self) -> None:
        """Encerra a sessão local."""

    # -- cofre de chaves --------------------------------------------------- #
    def obter_cofre(self) -> CofreRemoto | None:
        """Lê ``diary_keys`` do usuário logado (``None`` no primeiro acesso)."""

    def criar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        """Insere o cofre. Falha se já existir."""

    def atualizar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        """Substitui salt e DEK embrulhada (troca de passphrase)."""

    # -- notas ------------------------------------------------------------- #
    def listar_notas(self) -> list[NotaCifrada]:
        """Todas as notas visíveis para o usuário logado, mais recentes primeiro."""

    def criar_nota(self, title_cipher: str, content_cipher: str) -> NotaCifrada:
        """Insere uma nota já cifrada."""

    def atualizar_nota(
        self, nota_id: str, title_cipher: str, content_cipher: str
    ) -> NotaCifrada:
        """Atualiza uma nota. Deve falhar com ``AcessoNegado`` se não for do usuário."""

    def excluir_nota(self, nota_id: str) -> None:
        """Exclui uma nota. Deve falhar com ``AcessoNegado`` se não for do usuário."""

    def tentar_ler_nota(self, nota_id: str) -> NotaCifrada | None:
        """Tenta ler uma nota **por id**, sem filtrar por dono no código.

        Este método existe para a prova de isolamento: quem decide se a linha
        aparece é a camada de segurança (RLS no Postgres, política simulada no
        SQLite), não um ``WHERE user_id = ...`` escrito à mão pelo app.
        """


def criar_repositorio(configuracao=None) -> RepositorioDiario:
    """Fábrica: devolve o backend indicado pela configuração.

    Import tardio de propósito — quem roda em modo demonstração não precisa ter
    o pacote ``supabase`` instalado.
    """
    from .config import carregar_configuracao

    cfg = configuracao or carregar_configuracao()

    if cfg.usa_supabase:
        from .backends.supabase_backend import RepositorioSupabase

        return RepositorioSupabase(cfg.supabase_url, cfg.supabase_anon_key)

    from .backends.local_backend import RepositorioLocal

    return RepositorioLocal(cfg.caminho_banco_demo)
