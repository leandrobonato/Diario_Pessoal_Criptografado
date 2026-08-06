"""Criptografia ponta a ponta do diário.

O servidor nunca vê texto em claro nem a passphrase do usuário. Todo o
material sensível é cifrado aqui, no cliente, antes de qualquer chamada de
rede.

Arquitetura de chaves (envelope encryption)
-------------------------------------------

::

    passphrase do diário
            │
            │  Scrypt(salt aleatório, N=32768, r=8, p=1)   ← lento de propósito
            ▼
        KEK (32 bytes)  ─── nunca sai da memória do cliente
            │
            │  AES-256-GCM(aad="diary_key:<user_id>")
            ▼
    wrapped_dek (Base64)  ─── é isto que vai para o Postgres
            │
            │  desembrulha em memória
            ▼
        DEK (32 bytes)
            │
            │  AES-256-GCM(aad="note:<user_id>")
            ▼
    title_cipher / content_cipher (Base64)  ─── é isto que vai para o Postgres

Por que duas chaves em vez de cifrar tudo direto com a KEK?

* **Trocar a passphrase não reescreve nenhuma nota.** Basta derivar a nova KEK
  e re-embrulhar a mesma DEK: uma linha de UPDATE em ``diary_keys``.
* A DEK é aleatória de 32 bytes, não derivada de senha humana — o material
  que realmente protege as notas tem entropia máxima desde o primeiro dia.

Por que AES-GCM e não AES-CBC/Fernet?
-------------------------------------

GCM é AEAD: além de cifrar, autentica. Qualquer bit alterado no texto cifrado
**ou nos dados associados (AAD)** faz a decifragem falhar. Usamos o ``user_id``
como AAD, o que amarra criptograficamente cada envelope ao seu dono: mesmo que
alguém conseguisse burlar o RLS e copiar o ``content_cipher`` da Alice para uma
linha do Bruno, o texto não abriria — a AAD não bateria.

Por que Scrypt?
---------------

É um KDF *memory-hard*: encarece ataque de força bruta em GPU/ASIC, não só em
CPU. Com ``N=2**15, r=8, p=1`` o custo é de ~32 MB de RAM e ~100 ms por
derivação — imperceptível para o usuário, caríssimo para quem quer testar
bilhões de senhas. E vem na própria ``cryptography``, sem dependência extra.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import EnvelopeInvalido, PassphraseIncorreta

# --------------------------------------------------------------------------- #
# Parâmetros
# --------------------------------------------------------------------------- #

#: Versão do formato de envelope. Gravada junto de cada registro para permitir
#: evoluir o esquema criptográfico sem quebrar dados antigos.
CRYPTO_VERSION = 1

SCRYPT_N = 2**15  # 32768 — fator de custo de CPU/memória
SCRYPT_R = 8      # tamanho do bloco
SCRYPT_P = 1      # paralelismo
CHAVE_BYTES = 32  # AES-256
SALT_BYTES = 16
NONCE_BYTES = 12  # 96 bits: tamanho recomendado para GCM

#: Tamanho mínimo de senha aceito. Curto o bastante para não irritar, longo o
#: bastante para que o Scrypt faça diferença.
TAMANHO_MINIMO_PASSPHRASE = 8

KDF_PARAMS_PADRAO: dict[str, Any] = {
    "algorithm": "scrypt",
    "n": SCRYPT_N,
    "r": SCRYPT_R,
    "p": SCRYPT_P,
    "length": CHAVE_BYTES,
}


# --------------------------------------------------------------------------- #
# Helpers de codificação
# --------------------------------------------------------------------------- #
def b64e(dados: bytes) -> str:
    """Codifica bytes em Base64 ASCII (o formato guardado no Postgres)."""
    return base64.b64encode(dados).decode("ascii")


def b64d(texto: str) -> bytes:
    """Decodifica Base64, traduzindo lixo de entrada em :class:`EnvelopeInvalido`."""
    try:
        return base64.b64decode(texto.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as exc:  # pragma: no cover - trivial
        raise EnvelopeInvalido("Conteúdo cifrado não é Base64 válido.") from exc


# --------------------------------------------------------------------------- #
# Derivação de chaves
# --------------------------------------------------------------------------- #
def gerar_salt() -> bytes:
    """Gera um salt aleatório para o Scrypt.

    O salt é público (fica no banco em claro): sua função é impedir que a mesma
    senha, usada por dois usuários, gere a mesma KEK — e inviabilizar rainbow
    tables.
    """
    return secrets.token_bytes(SALT_BYTES)


def gerar_dek() -> bytes:
    """Gera uma DEK (Data Encryption Key) aleatória de 256 bits."""
    return secrets.token_bytes(CHAVE_BYTES)


def derivar_kek(passphrase: str, salt: bytes, params: dict[str, Any] | None = None) -> bytes:
    """Deriva a KEK (Key Encryption Key) a partir da passphrase do diário.

    Args:
        passphrase: senha do cofre, digitada pelo usuário. **Nunca** trafega
            pela rede nem é gravada em disco.
        salt: salt do Scrypt, recuperado de ``diary_keys.kdf_salt``.
        params: parâmetros do KDF gravados junto do salt. Permitem endurecer o
            custo para novos usuários sem invalidar cofres antigos.

    Returns:
        32 bytes de chave simétrica.
    """
    p = {**KDF_PARAMS_PADRAO, **(params or {})}
    kdf = Scrypt(
        salt=salt,
        length=int(p["length"]),
        n=int(p["n"]),
        r=int(p["r"]),
        p=int(p["p"]),
    )
    return kdf.derive(passphrase.encode("utf-8"))


# --------------------------------------------------------------------------- #
# Envelope AES-256-GCM
# --------------------------------------------------------------------------- #
def _cifrar_bytes(dados: bytes, chave: bytes, aad: bytes) -> str:
    """Cifra ``dados`` e devolve Base64 de ``nonce ‖ ciphertext ‖ tag``.

    O nonce é sorteado a cada chamada. Reutilizar nonce com a mesma chave é a
    falha catastrófica clássica do GCM (permite recuperar o texto em claro), e
    é por isso que ele nunca é derivado nem contado aqui: sempre aleatório.
    """
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(chave).encrypt(nonce, dados, aad)
    return b64e(nonce + ciphertext)


def _decifrar_bytes(envelope_b64: str, chave: bytes, aad: bytes) -> bytes:
    """Inverso de :func:`_cifrar_bytes`, validando a tag de autenticação."""
    bruto = b64d(envelope_b64)
    if len(bruto) <= NONCE_BYTES:
        raise EnvelopeInvalido("Envelope cifrado truncado.")
    nonce, ciphertext = bruto[:NONCE_BYTES], bruto[NONCE_BYTES:]
    try:
        return AESGCM(chave).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise EnvelopeInvalido(
            "Conteúdo cifrado inválido: chave incorreta ou dado adulterado."
        ) from exc


def aad_nota(user_id: str) -> bytes:
    """Dados associados de uma nota — amarram o envelope ao dono da linha."""
    return f"note:{user_id}".encode("utf-8")


def aad_cofre(user_id: str) -> bytes:
    """Dados associados do cofre de chaves."""
    return f"diary_key:{user_id}".encode("utf-8")


def cifrar_texto(texto: str, dek: bytes, user_id: str) -> str:
    """Cifra um trecho de texto do diário (título ou conteúdo)."""
    return _cifrar_bytes(texto.encode("utf-8"), dek, aad_nota(user_id))


def decifrar_texto(envelope_b64: str, dek: bytes, user_id: str) -> str:
    """Decifra um trecho de texto do diário."""
    return _decifrar_bytes(envelope_b64, dek, aad_nota(user_id)).decode("utf-8")


def embrulhar_dek(dek: bytes, kek: bytes, user_id: str) -> str:
    """Embrulha (cifra) a DEK com a KEK — resultado vai para ``diary_keys``."""
    return _cifrar_bytes(dek, kek, aad_cofre(user_id))


def desembrulhar_dek(wrapped_dek_b64: str, kek: bytes, user_id: str) -> bytes:
    """Desembrulha a DEK.

    Falha aqui significa, na esmagadora maioria das vezes, passphrase errada —
    por isso a exceção é :class:`PassphraseIncorreta` e não
    :class:`EnvelopeInvalido`.
    """
    try:
        return _decifrar_bytes(wrapped_dek_b64, kek, aad_cofre(user_id))
    except EnvelopeInvalido as exc:
        raise PassphraseIncorreta("Passphrase do diário incorreta.") from exc


# --------------------------------------------------------------------------- #
# Cofre
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MaterialDoCofre:
    """O que precisa ser persistido em ``public.diary_keys``.

    Nada aqui é segredo: são o salt (público por definição) e a DEK já cifrada.
    """

    kdf_salt: str
    wrapped_dek: str
    kdf_params: dict[str, Any]
    crypto_version: int = CRYPTO_VERSION


def criar_material_do_cofre(passphrase: str, user_id: str) -> tuple[MaterialDoCofre, bytes]:
    """Cria um cofre novo para o usuário.

    Returns:
        Tupla ``(material_para_o_banco, dek_em_memoria)``. A DEK fica só na
        sessão do cliente; o banco recebe apenas a versão embrulhada.
    """
    validar_passphrase(passphrase)
    salt = gerar_salt()
    kek = derivar_kek(passphrase, salt)
    dek = gerar_dek()
    material = MaterialDoCofre(
        kdf_salt=b64e(salt),
        wrapped_dek=embrulhar_dek(dek, kek, user_id),
        kdf_params=dict(KDF_PARAMS_PADRAO),
    )
    return material, dek


def abrir_cofre(passphrase: str, material: MaterialDoCofre, user_id: str) -> bytes:
    """Recupera a DEK a partir da passphrase e do material guardado no banco.

    Raises:
        PassphraseIncorreta: se a passphrase não abrir o cofre.
    """
    kek = derivar_kek(passphrase, b64d(material.kdf_salt), material.kdf_params)
    return desembrulhar_dek(material.wrapped_dek, kek, user_id)


def reembrulhar_dek(
    dek: bytes, nova_passphrase: str, user_id: str
) -> MaterialDoCofre:
    """Gera o material do cofre para uma passphrase nova, mantendo a MESMA DEK.

    É o que torna a troca de senha instantânea: nenhuma nota precisa ser lida,
    decifrada ou reescrita.
    """
    validar_passphrase(nova_passphrase)
    salt = gerar_salt()
    kek = derivar_kek(nova_passphrase, salt)
    return MaterialDoCofre(
        kdf_salt=b64e(salt),
        wrapped_dek=embrulhar_dek(dek, kek, user_id),
        kdf_params=dict(KDF_PARAMS_PADRAO),
    )


def validar_passphrase(passphrase: str) -> None:
    """Valida o tamanho mínimo da passphrase do diário."""
    if len(passphrase) < TAMANHO_MINIMO_PASSPHRASE:
        raise ValueError(
            f"A passphrase do diário precisa de pelo menos "
            f"{TAMANHO_MINIMO_PASSPHRASE} caracteres."
        )


def serializar_kdf_params(params: dict[str, Any]) -> str:
    """Serializa os parâmetros do KDF para a coluna ``jsonb``."""
    return json.dumps(params, sort_keys=True)
