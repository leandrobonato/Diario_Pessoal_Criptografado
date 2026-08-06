"""Testes da camada de criptografia.

O que importa aqui não é "cifra e decifra" — é que as garantias que o README
promete sejam verdadeiras: passphrase errada não abre, envelope adulterado não
abre, envelope de outro usuário não abre, e trocar a senha não invalida nada.
"""

from __future__ import annotations

import base64

import pytest

from diario import crypto
from diario.errors import EnvelopeInvalido, PassphraseIncorreta

USER_A = "11111111-1111-1111-1111-111111111111"
USER_B = "22222222-2222-2222-2222-222222222222"


def test_ciclo_completo_do_cofre():
    material, dek = crypto.criar_material_do_cofre("passphrase-boa", USER_A)
    recuperada = crypto.abrir_cofre("passphrase-boa", material, USER_A)
    assert recuperada == dek
    assert len(dek) == 32


def test_passphrase_errada_nao_abre_o_cofre():
    material, _ = crypto.criar_material_do_cofre("passphrase-boa", USER_A)
    with pytest.raises(PassphraseIncorreta):
        crypto.abrir_cofre("passphrase-ruim", material, USER_A)


def test_cofre_de_um_usuario_nao_abre_com_o_id_de_outro():
    """A AAD amarra o envelope ao dono: o mesmo segredo, outro user_id, não abre."""
    material, _ = crypto.criar_material_do_cofre("passphrase-boa", USER_A)
    with pytest.raises(PassphraseIncorreta):
        crypto.abrir_cofre("passphrase-boa", material, USER_B)


def test_texto_volta_intacto():
    dek = crypto.gerar_dek()
    original = "Linha 1\nLinha 2 com acento: coração, ãõç 😀"
    envelope = crypto.cifrar_texto(original, dek, USER_A)
    assert crypto.decifrar_texto(envelope, dek, USER_A) == original


def test_mesmo_texto_gera_envelopes_diferentes():
    """Nonce aleatório por chamada: dois envelopes iguais nunca aparecem."""
    dek = crypto.gerar_dek()
    a = crypto.cifrar_texto("mesmo texto", dek, USER_A)
    b = crypto.cifrar_texto("mesmo texto", dek, USER_A)
    assert a != b
    assert crypto.decifrar_texto(a, dek, USER_A) == crypto.decifrar_texto(b, dek, USER_A)


def test_envelope_nao_vaza_o_texto_em_claro():
    dek = crypto.gerar_dek()
    envelope = crypto.cifrar_texto("segredo absoluto", dek, USER_A)
    assert "segredo" not in envelope
    assert b"segredo" not in base64.b64decode(envelope)


def test_envelope_adulterado_e_rejeitado():
    """Um único bit trocado invalida a tag do AES-GCM."""
    dek = crypto.gerar_dek()
    envelope = crypto.cifrar_texto("conteúdo íntegro", dek, USER_A)
    bruto = bytearray(base64.b64decode(envelope))
    bruto[-1] ^= 0x01
    adulterado = base64.b64encode(bytes(bruto)).decode()
    with pytest.raises(EnvelopeInvalido):
        crypto.decifrar_texto(adulterado, dek, USER_A)


def test_nota_copiada_para_outro_usuario_nao_abre():
    """Cenário: alguém burla o RLS e copia o ciphertext para outra linha.

    Mesmo com a chave correta, a AAD (``note:<user_id>``) não bate e o texto
    não abre. É a segunda barreira funcionando.
    """
    dek = crypto.gerar_dek()
    envelope = crypto.cifrar_texto("diário da Alice", dek, USER_A)
    with pytest.raises(EnvelopeInvalido):
        crypto.decifrar_texto(envelope, dek, USER_B)


def test_chave_errada_nao_abre_a_nota():
    envelope = crypto.cifrar_texto("texto", crypto.gerar_dek(), USER_A)
    with pytest.raises(EnvelopeInvalido):
        crypto.decifrar_texto(envelope, crypto.gerar_dek(), USER_A)


def test_salts_diferentes_para_a_mesma_passphrase():
    """Duas contas com a mesma senha não compartilham chave nem envelope."""
    m1, _ = crypto.criar_material_do_cofre("mesma-passphrase", USER_A)
    m2, _ = crypto.criar_material_do_cofre("mesma-passphrase", USER_B)
    assert m1.kdf_salt != m2.kdf_salt
    assert m1.wrapped_dek != m2.wrapped_dek


def test_troca_de_passphrase_preserva_a_dek():
    """O ponto do envelope encryption: a DEK sobrevive à troca de senha."""
    material, dek = crypto.criar_material_do_cofre("senha-antiga", USER_A)
    nota = crypto.cifrar_texto("nota escrita antes da troca", dek, USER_A)

    novo_material = crypto.reembrulhar_dek(dek, "senha-nova-melhor", USER_A)
    dek_recuperada = crypto.abrir_cofre("senha-nova-melhor", novo_material, USER_A)

    assert dek_recuperada == dek
    assert crypto.decifrar_texto(nota, dek_recuperada, USER_A) == "nota escrita antes da troca"
    with pytest.raises(PassphraseIncorreta):
        crypto.abrir_cofre("senha-antiga", novo_material, USER_A)


def test_passphrase_curta_e_recusada():
    with pytest.raises(ValueError):
        crypto.criar_material_do_cofre("1234", USER_A)


def test_base64_invalido_vira_erro_de_dominio():
    with pytest.raises(EnvelopeInvalido):
        crypto.decifrar_texto("isto não é base64!!!", crypto.gerar_dek(), USER_A)


def test_envelope_truncado_e_rejeitado():
    dek = crypto.gerar_dek()
    envelope = crypto.cifrar_texto("qualquer coisa", dek, USER_A)
    truncado = base64.b64encode(base64.b64decode(envelope)[:8]).decode()
    with pytest.raises(EnvelopeInvalido):
        crypto.decifrar_texto(truncado, dek, USER_A)


def test_parametros_do_kdf_sao_persistidos_com_o_cofre():
    """Sem os parâmetros gravados, cofres antigos quebrariam ao endurecer o KDF."""
    material, _ = crypto.criar_material_do_cofre("passphrase-boa", USER_A)
    assert material.kdf_params["algorithm"] == "scrypt"
    assert material.kdf_params["n"] == crypto.SCRYPT_N
    assert material.crypto_version == crypto.CRYPTO_VERSION
