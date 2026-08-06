"""Backend de demonstração em SQLite.

**Para que serve:** permitir que qualquer pessoa clone o repositório e rode o
diário em 30 segundos, sem criar conta no Supabase e sem Docker. É o modo em
que os testes automatizados rodam.

**O que ele NÃO é:** prova de que o RLS funciona. O SQLite não tem Row Level
Security; aqui as mesmas regras são reproduzidas na camada de aplicação, com a
mesma semântica das policies do Postgres:

===========================  ==================================================
Policy no Postgres           Equivalente aqui
===========================  ==================================================
``using (auth.uid() = ...)``  :meth:`PoliticaDeLinha.predicado` injetado em
                              todo SELECT/UPDATE/DELETE
``with check (...)``          :meth:`PoliticaDeLinha.validar_gravacao`
``default auth.uid()``        o ``user_id`` nunca vem do chamador
===========================  ==================================================

A prova de verdade — RLS real, rodando dentro do Postgres — está em
``supabase/tests/rls_notes_test.sql`` e em ``scripts/verificar_rls.py``.

Um detalhe fiel ao original: quando a linha existe mas é de outro usuário, o
comportamento é **idêntico** ao de linha inexistente. É assim que o RLS se
comporta (o filtro roda antes do ``WHERE``), e é assim que deve ser — do
contrário a própria mensagem de erro viraria um oráculo de existência.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..crypto import MaterialDoCofre
from ..errors import (
    AcessoNegado,
    AutenticacaoError,
    CofreJaExiste,
    SessaoInexistente,
)
from ..models import CofreRemoto, NotaCifrada, Sessao

# Parâmetros do hash de senha da conta (não confundir com o KDF do cofre:
# aquele protege as notas, este só autentica o login do modo demonstração).
_SENHA_N = 2**14
_SENHA_R = 8
_SENHA_P = 1


class PoliticaDeLinha:
    """Tradução, em Python, da regra ``auth.uid() = user_id``.

    Concentrar a regra numa classe única é o ponto: não existe consulta no
    backend local que escape dela, assim como não existe consulta no Postgres
    que escape do RLS.
    """

    def __init__(self, coluna: str = "user_id") -> None:
        self.coluna = coluna

    def predicado(self) -> str:
        """Fragmento SQL equivalente à cláusula ``USING`` da policy."""
        return f"{self.coluna} = :uid"

    def validar_gravacao(self, user_id_da_linha: str, uid: str) -> None:
        """Equivalente à cláusula ``WITH CHECK``: só grava linha própria."""
        if user_id_da_linha != uid:
            raise AcessoNegado(
                "WITH CHECK violado: tentativa de gravar linha de outro usuário."
            )


class RepositorioLocal:
    """Implementa :class:`diario.repository.RepositorioDiario` sobre SQLite."""

    nome = "Demonstração local (SQLite)"
    remoto = False

    def __init__(self, caminho_banco: str | Path) -> None:
        self._caminho = Path(caminho_banco)
        self._caminho.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._caminho, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("pragma foreign_keys = on")
        self._politica = PoliticaDeLinha()
        self._sessao: Sessao | None = None
        self._criar_schema()

    # ------------------------------------------------------------------ #
    # Infraestrutura
    # ------------------------------------------------------------------ #
    def _criar_schema(self) -> None:
        """Espelha o schema das migrations do Supabase."""
        self._conn.executescript(
            """
            create table if not exists users (
                id            text primary key,
                email         text not null unique collate nocase,
                senha_salt    text not null,
                senha_hash    text not null,
                created_at    text not null
            );

            create table if not exists diary_keys (
                user_id        text primary key references users(id) on delete cascade,
                kdf_salt       text not null,
                kdf_params     text not null,
                wrapped_dek    text not null,
                crypto_version integer not null default 1,
                created_at     text not null,
                updated_at     text not null
            );

            create table if not exists notes (
                id             text primary key,
                user_id        text not null references users(id) on delete cascade,
                title_cipher   text not null,
                content_cipher text not null,
                crypto_version integer not null default 1,
                created_at     text not null,
                updated_at     text not null
            );

            create index if not exists notes_user_id_created_at_idx
                on notes (user_id, created_at desc);
            """
        )
        self._conn.commit()

    def _uid(self) -> str:
        if self._sessao is None:
            raise SessaoInexistente("Nenhum usuário autenticado nesta sessão.")
        return self._sessao.user_id

    def _consultar(self, sql: str, params: dict[str, Any]) -> Iterable[sqlite3.Row]:
        return self._conn.execute(sql, params).fetchall()

    @staticmethod
    def _agora() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------ #
    # Autenticação
    # ------------------------------------------------------------------ #
    @property
    def sessao(self) -> Sessao | None:
        return self._sessao

    @staticmethod
    def _hash_senha(senha: str, salt: bytes) -> str:
        derivado = hashlib.scrypt(
            senha.encode("utf-8"), salt=salt, n=_SENHA_N, r=_SENHA_R, p=_SENHA_P, dklen=32
        )
        return derivado.hex()

    def criar_conta(self, email: str, senha: str) -> Sessao:
        email = email.strip().lower()
        if not email or "@" not in email:
            raise AutenticacaoError("Informe um e-mail válido.")
        if len(senha) < 6:
            raise AutenticacaoError("A senha da conta precisa de pelo menos 6 caracteres.")

        salt = secrets.token_bytes(16)
        user_id = str(uuid.uuid4())
        try:
            self._conn.execute(
                "insert into users (id, email, senha_salt, senha_hash, created_at)"
                " values (:id, :email, :salt, :hash, :agora)",
                {
                    "id": user_id,
                    "email": email,
                    "salt": salt.hex(),
                    "hash": self._hash_senha(senha, salt),
                    "agora": self._agora(),
                },
            )
        except sqlite3.IntegrityError as exc:
            raise AutenticacaoError("Já existe uma conta com este e-mail.") from exc
        self._conn.commit()

        self._sessao = Sessao(user_id=user_id, email=email)
        return self._sessao

    def entrar(self, email: str, senha: str) -> Sessao:
        email = email.strip().lower()
        linha = self._conn.execute(
            "select * from users where email = :email", {"email": email}
        ).fetchone()
        if linha is None:
            # Mensagem genérica de propósito: não confirmamos se o e-mail existe.
            raise AutenticacaoError("E-mail ou senha inválidos.")

        esperado = linha["senha_hash"]
        calculado = self._hash_senha(senha, bytes.fromhex(linha["senha_salt"]))
        if not secrets.compare_digest(esperado, calculado):
            raise AutenticacaoError("E-mail ou senha inválidos.")

        self._sessao = Sessao(user_id=linha["id"], email=linha["email"])
        return self._sessao

    def sair(self) -> None:
        self._sessao = None

    # ------------------------------------------------------------------ #
    # Cofre de chaves
    # ------------------------------------------------------------------ #
    def obter_cofre(self) -> CofreRemoto | None:
        uid = self._uid()
        linha = self._conn.execute(
            f"select * from diary_keys where {self._politica.predicado()}", {"uid": uid}
        ).fetchone()
        return CofreRemoto.de_dict(dict(linha)) if linha else None

    def criar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        uid = self._uid()
        self._politica.validar_gravacao(uid, uid)  # WITH CHECK: dono = eu
        agora = self._agora()
        try:
            self._conn.execute(
                "insert into diary_keys"
                " (user_id, kdf_salt, kdf_params, wrapped_dek, crypto_version, created_at, updated_at)"
                " values (:uid, :salt, :params, :dek, :versao, :agora, :agora)",
                {
                    "uid": uid,
                    "salt": material.kdf_salt,
                    "params": json.dumps(material.kdf_params, sort_keys=True),
                    "dek": material.wrapped_dek,
                    "versao": material.crypto_version,
                    "agora": agora,
                },
            )
        except sqlite3.IntegrityError as exc:
            raise CofreJaExiste("Este usuário já possui um cofre.") from exc
        self._conn.commit()
        cofre = self.obter_cofre()
        assert cofre is not None
        return cofre

    def atualizar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        uid = self._uid()
        cursor = self._conn.execute(
            "update diary_keys set kdf_salt = :salt, kdf_params = :params,"
            " wrapped_dek = :dek, crypto_version = :versao, updated_at = :agora"
            f" where {self._politica.predicado()}",
            {
                "uid": uid,
                "salt": material.kdf_salt,
                "params": json.dumps(material.kdf_params, sort_keys=True),
                "dek": material.wrapped_dek,
                "versao": material.crypto_version,
                "agora": self._agora(),
            },
        )
        if cursor.rowcount == 0:
            raise AcessoNegado("Nenhum cofre acessível para atualizar.")
        self._conn.commit()
        cofre = self.obter_cofre()
        assert cofre is not None
        return cofre

    # ------------------------------------------------------------------ #
    # Notas
    # ------------------------------------------------------------------ #
    def listar_notas(self) -> list[NotaCifrada]:
        uid = self._uid()
        linhas = self._consultar(
            f"select * from notes where {self._politica.predicado()}"
            " order by created_at desc",
            {"uid": uid},
        )
        return [NotaCifrada.de_dict(dict(linha)) for linha in linhas]

    def criar_nota(self, title_cipher: str, content_cipher: str) -> NotaCifrada:
        uid = self._uid()
        # Equivalente ao "default auth.uid()" da coluna: o dono nunca é
        # informado pelo chamador, é sempre a sessão atual.
        self._politica.validar_gravacao(uid, uid)
        nota_id = str(uuid.uuid4())
        agora = self._agora()
        self._conn.execute(
            "insert into notes"
            " (id, user_id, title_cipher, content_cipher, crypto_version, created_at, updated_at)"
            " values (:id, :uid, :titulo, :conteudo, 1, :agora, :agora)",
            {
                "id": nota_id,
                "uid": uid,
                "titulo": title_cipher,
                "conteudo": content_cipher,
                "agora": agora,
            },
        )
        self._conn.commit()
        nota = self.tentar_ler_nota(nota_id)
        assert nota is not None
        return nota

    def atualizar_nota(
        self, nota_id: str, title_cipher: str, content_cipher: str
    ) -> NotaCifrada:
        uid = self._uid()
        cursor = self._conn.execute(
            "update notes set title_cipher = :titulo, content_cipher = :conteudo,"
            " updated_at = :agora"
            f" where id = :id and {self._politica.predicado()}",
            {
                "id": nota_id,
                "uid": uid,
                "titulo": title_cipher,
                "conteudo": content_cipher,
                "agora": self._agora(),
            },
        )
        if cursor.rowcount == 0:
            raise AcessoNegado("Nota inexistente ou pertencente a outro usuário.")
        self._conn.commit()
        nota = self.tentar_ler_nota(nota_id)
        assert nota is not None
        return nota

    def excluir_nota(self, nota_id: str) -> None:
        uid = self._uid()
        cursor = self._conn.execute(
            f"delete from notes where id = :id and {self._politica.predicado()}",
            {"id": nota_id, "uid": uid},
        )
        if cursor.rowcount == 0:
            raise AcessoNegado("Nota inexistente ou pertencente a outro usuário.")
        self._conn.commit()

    def tentar_ler_nota(self, nota_id: str) -> NotaCifrada | None:
        uid = self._uid()
        linha = self._conn.execute(
            f"select * from notes where id = :id and {self._politica.predicado()}",
            {"id": nota_id, "uid": uid},
        ).fetchone()
        return NotaCifrada.de_dict(dict(linha)) if linha else None

    # ------------------------------------------------------------------ #
    # Diagnóstico (usado pela tela "Prova de isolamento")
    # ------------------------------------------------------------------ #
    def contar_notas_no_banco(self) -> int:
        """Conta **todas** as linhas da tabela, ignorando a política.

        Só existe para a demonstração: comparar este número com o total que o
        usuário enxerga é o que torna o isolamento visível na tela.
        """
        return int(self._conn.execute("select count(*) from notes").fetchone()[0])

    def fechar(self) -> None:
        self._conn.close()
