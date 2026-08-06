"""Serviço do diário: a cola entre criptografia e persistência.

É a única camada que enxerga texto em claro **e** falar com o repositório —
e é justamente por isso que ela é curta e sem exceção: toda escrita passa por
:func:`diario.crypto.cifrar_texto`, toda leitura por
:func:`diario.crypto.decifrar_texto`. A UI nunca toca no repositório direto.

Estados possíveis de uma sessão::

    deslogado ──entrar()──► logado / cofre bloqueado ──desbloquear()──► cofre aberto
                                    │                                        │
                                    └───────────── sair() / bloquear() ──────┘

A DEK vive apenas em memória, e apenas enquanto o cofre estiver aberto.
"""

from __future__ import annotations

from typing import Literal

from . import crypto
from .crypto import MaterialDoCofre
from .errors import CofreInexistente, DiarioError, SessaoInexistente
from .models import Nota, NotaCifrada, Sessao
from .repository import RepositorioDiario

StatusCofre = Literal["inexistente", "bloqueado", "aberto"]


class DiarioService:
    """Casos de uso do diário, independentes de interface."""

    def __init__(self, repositorio: RepositorioDiario) -> None:
        self._repo = repositorio
        self._dek: bytes | None = None

    # ------------------------------------------------------------------ #
    # Sessão
    # ------------------------------------------------------------------ #
    @property
    def repositorio(self) -> RepositorioDiario:
        return self._repo

    @property
    def sessao(self) -> Sessao | None:
        return self._repo.sessao

    @property
    def logado(self) -> bool:
        return self._repo.sessao is not None

    @property
    def cofre_aberto(self) -> bool:
        return self._dek is not None

    def criar_conta(self, email: str, senha: str) -> Sessao:
        self._dek = None
        return self._repo.criar_conta(email, senha)

    def entrar(self, email: str, senha: str) -> Sessao:
        self._dek = None
        return self._repo.entrar(email, senha)

    def sair(self) -> None:
        self.bloquear()
        self._repo.sair()

    # ------------------------------------------------------------------ #
    # Cofre
    # ------------------------------------------------------------------ #
    def status_do_cofre(self) -> StatusCofre:
        if self._dek is not None:
            return "aberto"
        return "bloqueado" if self._repo.obter_cofre() is not None else "inexistente"

    def criar_cofre(self, passphrase: str) -> None:
        """Primeiro acesso: gera salt + DEK e grava o cofre já embrulhado."""
        sessao = self._exigir_sessao()
        material, dek = crypto.criar_material_do_cofre(passphrase, sessao.user_id)
        self._repo.criar_cofre(material)
        self._dek = dek

    def desbloquear(self, passphrase: str) -> None:
        """Deriva a KEK, desembrulha a DEK e deixa o diário legível."""
        sessao = self._exigir_sessao()
        cofre = self._repo.obter_cofre()
        if cofre is None:
            raise CofreInexistente("Este usuário ainda não criou o cofre do diário.")
        material = MaterialDoCofre(
            kdf_salt=cofre.kdf_salt,
            wrapped_dek=cofre.wrapped_dek,
            kdf_params=cofre.kdf_params,
            crypto_version=cofre.crypto_version,
        )
        self._dek = crypto.abrir_cofre(passphrase, material, sessao.user_id)

    def bloquear(self) -> None:
        """Esquece a DEK. As notas voltam a ser bytes opacos."""
        self._dek = None

    def trocar_passphrase(self, passphrase_atual: str, nova_passphrase: str) -> None:
        """Troca a senha do diário sem reescrever uma única nota.

        Só o envelope da DEK é refeito — as notas continuam cifradas com a
        mesma DEK de sempre.
        """
        sessao = self._exigir_sessao()
        self.desbloquear(passphrase_atual)
        assert self._dek is not None
        novo_material = crypto.reembrulhar_dek(self._dek, nova_passphrase, sessao.user_id)
        self._repo.atualizar_cofre(novo_material)

    # ------------------------------------------------------------------ #
    # Notas
    # ------------------------------------------------------------------ #
    def listar_notas(self) -> list[Nota]:
        dek, sessao = self._exigir_cofre()
        return [self._decifrar(n, dek, sessao.user_id) for n in self._repo.listar_notas()]

    def criar_nota(self, titulo: str, conteudo: str) -> Nota:
        dek, sessao = self._exigir_cofre()
        titulo = titulo.strip() or "Sem título"
        cifrada = self._repo.criar_nota(
            crypto.cifrar_texto(titulo, dek, sessao.user_id),
            crypto.cifrar_texto(conteudo, dek, sessao.user_id),
        )
        return self._decifrar(cifrada, dek, sessao.user_id)

    def atualizar_nota(self, nota_id: str, titulo: str, conteudo: str) -> Nota:
        dek, sessao = self._exigir_cofre()
        titulo = titulo.strip() or "Sem título"
        cifrada = self._repo.atualizar_nota(
            nota_id,
            crypto.cifrar_texto(titulo, dek, sessao.user_id),
            crypto.cifrar_texto(conteudo, dek, sessao.user_id),
        )
        return self._decifrar(cifrada, dek, sessao.user_id)

    def excluir_nota(self, nota_id: str) -> None:
        self._exigir_cofre()
        self._repo.excluir_nota(nota_id)

    def buscar(self, termo: str) -> list[Nota]:
        """Busca textual — obrigatoriamente **no cliente**.

        Consequência direta da criptografia ponta a ponta: o servidor guarda
        bytes opacos, então não existe ``ilike`` nem índice de texto do lado do
        Postgres. Para um diário pessoal (dezenas a centenas de notas) isso é
        irrelevante; num produto com milhares de registros por usuário, o
        caminho seria índice cifrado / busca por tokens com hash cego.
        """
        termo = termo.strip().lower()
        if not termo:
            return self.listar_notas()
        return [
            nota
            for nota in self.listar_notas()
            if termo in nota.titulo.lower() or termo in nota.conteudo.lower()
        ]

    # ------------------------------------------------------------------ #
    # Prova de isolamento (usada pela tela de demonstração e pelos scripts)
    # ------------------------------------------------------------------ #
    def tentar_ler_nota_por_id(self, nota_id: str) -> Nota | None:
        """Tenta abrir uma nota por id, sem filtrar por dono no código.

        Se o id for de outro usuário, a resposta vem vazia — barrado pelo RLS
        (Supabase) ou pela política equivalente (modo demonstração).
        """
        dek, sessao = self._exigir_cofre()
        cifrada = self._repo.tentar_ler_nota(nota_id)
        return self._decifrar(cifrada, dek, sessao.user_id) if cifrada else None

    # ------------------------------------------------------------------ #
    # Internos
    # ------------------------------------------------------------------ #
    @staticmethod
    def _decifrar(nota: NotaCifrada, dek: bytes, user_id: str) -> Nota:
        return Nota(
            id=nota.id,
            titulo=crypto.decifrar_texto(nota.title_cipher, dek, user_id),
            conteudo=crypto.decifrar_texto(nota.content_cipher, dek, user_id),
            created_at=nota.created_at,
            updated_at=nota.updated_at,
        )

    def _exigir_sessao(self) -> Sessao:
        sessao = self._repo.sessao
        if sessao is None:
            raise SessaoInexistente("Faça login antes de continuar.")
        return sessao

    def _exigir_cofre(self) -> tuple[bytes, Sessao]:
        sessao = self._exigir_sessao()
        if self._dek is None:
            raise DiarioError("O cofre está bloqueado. Informe a passphrase do diário.")
        return self._dek, sessao
