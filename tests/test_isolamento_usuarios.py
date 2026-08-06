"""Isolamento por usuário — o coração do desafio de RLS.

Estes testes rodam no backend de demonstração (SQLite), onde a regra
``auth.uid() = user_id`` é reproduzida em Python. A verificação equivalente
rodando dentro do PostgreSQL está em ``supabase/tests/rls_notes_test.sql``
(pgTAP) e em ``scripts/verificar_rls.py`` (contra um projeto Supabase real).

Cada teste aqui tem um irmão lá — de propósito: a mesma expectativa, escrita
duas vezes, nas duas camadas.
"""

from __future__ import annotations

import pytest

from conftest import PASSPHRASE_ALICE, PASSPHRASE_BRUNO, entrar_como_bruno
from diario.errors import AcessoNegado, SessaoInexistente
from diario.service import DiarioService


def test_usuario_ve_apenas_as_proprias_notas(servico_com_alice: DiarioService):
    servico = servico_com_alice
    assert len(servico.listar_notas()) == 1

    entrar_como_bruno(servico)
    assert servico.listar_notas() == []

    servico.criar_nota("Nota do Bruno", "conteúdo do Bruno")
    titulos = [n.titulo for n in servico.listar_notas()]
    assert titulos == ["Nota do Bruno"]


def test_select_por_id_nao_alcanca_nota_alheia(servico_com_alice: DiarioService):
    servico = servico_com_alice
    id_da_alice = servico.listar_notas()[0].id

    entrar_como_bruno(servico)
    assert servico.tentar_ler_nota_por_id(id_da_alice) is None


def test_update_em_nota_alheia_e_bloqueado(servico_com_alice: DiarioService):
    servico = servico_com_alice
    id_da_alice = servico.listar_notas()[0].id

    entrar_como_bruno(servico)
    with pytest.raises(AcessoNegado):
        servico.atualizar_nota(id_da_alice, "invadido", "invadido")


def test_delete_em_nota_alheia_e_bloqueado(servico_com_alice: DiarioService):
    servico = servico_com_alice
    id_da_alice = servico.listar_notas()[0].id

    entrar_como_bruno(servico)
    with pytest.raises(AcessoNegado):
        servico.excluir_nota(id_da_alice)


def test_nota_alheia_permanece_intacta_apos_tentativas(servico_com_alice: DiarioService):
    servico = servico_com_alice
    nota = servico.listar_notas()[0]

    entrar_como_bruno(servico)
    for tentativa in (
        lambda: servico.atualizar_nota(nota.id, "x", "x"),
        lambda: servico.excluir_nota(nota.id),
    ):
        with pytest.raises(AcessoNegado):
            tentativa()

    servico.sair()
    servico.entrar("alice@exemplo.test", "senha-da-conta")
    servico.desbloquear(PASSPHRASE_ALICE)
    restaurada = servico.listar_notas()[0]
    assert restaurada.titulo == nota.titulo
    assert restaurada.conteudo == nota.conteudo


def test_cofre_de_chaves_tambem_e_isolado(servico_com_alice: DiarioService):
    servico = servico_com_alice
    cofre_alice = servico.repositorio.obter_cofre()
    assert cofre_alice is not None

    entrar_como_bruno(servico)
    cofre_bruno = servico.repositorio.obter_cofre()
    assert cofre_bruno is not None
    assert cofre_bruno.user_id != cofre_alice.user_id
    assert cofre_bruno.wrapped_dek != cofre_alice.wrapped_dek


def test_linha_existe_no_banco_mas_nao_para_o_outro_usuario(
    servico_com_alice: DiarioService,
):
    """O dado está lá — o que muda é quem consegue alcançá-lo."""
    servico = servico_com_alice
    entrar_como_bruno(servico)
    servico.criar_nota("Nota do Bruno", "conteúdo")

    assert servico.repositorio.contar_notas_no_banco() == 2  # total físico
    assert len(servico.listar_notas()) == 1                  # o que o Bruno vê


def test_operacoes_exigem_sessao(servico: DiarioService):
    with pytest.raises(SessaoInexistente):
        servico.repositorio.listar_notas()


def test_cofre_de_bruno_nao_abre_com_a_passphrase_de_alice(
    servico_com_alice: DiarioService,
):
    servico = servico_com_alice
    entrar_como_bruno(servico)
    servico.bloquear()

    from diario.errors import PassphraseIncorreta

    with pytest.raises(PassphraseIncorreta):
        servico.desbloquear(PASSPHRASE_ALICE)

    servico.desbloquear(PASSPHRASE_BRUNO)
    assert servico.cofre_aberto
