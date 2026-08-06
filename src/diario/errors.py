"""Exceções do domínio do diário.

Todas as falhas previsíveis do app derivam de :class:`DiarioError`, o que
permite à camada de UI tratar erro de negócio (mensagem amigável) sem engolir
erro de programação (que deve estourar).
"""

from __future__ import annotations


class DiarioError(Exception):
    """Base de todas as falhas de negócio do diário."""


# --------------------------------------------------------------------------- #
# Criptografia
# --------------------------------------------------------------------------- #
class CriptografiaError(DiarioError):
    """Base das falhas do módulo de criptografia."""


class PassphraseIncorreta(CriptografiaError):
    """A passphrase informada não abre o cofre.

    Na prática: a KEK derivada não valida a tag de autenticação do AES-GCM ao
    desembrulhar a DEK. Não há como distinguir "senha errada" de "cofre
    corrompido" — e isso é proposital, para não vazar informação.
    """


class EnvelopeInvalido(CriptografiaError):
    """O texto cifrado está corrompido, truncado ou foi adulterado.

    O AES-GCM detecta qualquer alteração de um único bit, inclusive nos dados
    associados (AAD) — que aqui carregam o ``user_id`` do dono.
    """


# --------------------------------------------------------------------------- #
# Autenticação e acesso
# --------------------------------------------------------------------------- #
class AutenticacaoError(DiarioError):
    """Credenciais inválidas, e-mail já cadastrado ou sessão expirada."""


class SessaoInexistente(DiarioError):
    """Alguma operação exigiu usuário logado e não havia sessão ativa."""


class AcessoNegado(DiarioError):
    """A operação alcançou uma linha que não pertence ao usuário.

    No backend Supabase isso corresponde a um ``UPDATE``/``DELETE`` que afetou
    zero linhas por causa do RLS, ou a um ``INSERT`` recusado pelo ``WITH
    CHECK`` (SQLSTATE 42501).
    """


class CofreInexistente(DiarioError):
    """O usuário ainda não criou o cofre de chaves (primeiro acesso)."""


class CofreJaExiste(DiarioError):
    """Tentativa de criar um segundo cofre para o mesmo usuário."""


class BackendIndisponivel(DiarioError):
    """O backend escolhido não pôde ser inicializado.

    Exemplos: variáveis ``SUPABASE_URL``/``SUPABASE_ANON_KEY`` ausentes, ou
    pacote ``supabase`` não instalado.
    """
