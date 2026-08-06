"""Fluxos do diário: cofre, CRUD e busca."""

from __future__ import annotations

import pytest

from conftest import PASSPHRASE_ALICE
from diario.errors import (
    AutenticacaoError,
    CofreInexistente,
    DiarioError,
    PassphraseIncorreta,
)
from diario.service import DiarioService


def test_estados_do_cofre(servico: DiarioService):
    servico.criar_conta("alice@exemplo.test", "senha-da-conta")
    assert servico.status_do_cofre() == "inexistente"

    servico.criar_cofre(PASSPHRASE_ALICE)
    assert servico.status_do_cofre() == "aberto"

    servico.bloquear()
    assert servico.status_do_cofre() == "bloqueado"

    servico.desbloquear(PASSPHRASE_ALICE)
    assert servico.status_do_cofre() == "aberto"


def test_notas_ficam_ilegiveis_com_o_cofre_bloqueado(servico_com_alice: DiarioService):
    servico_com_alice.bloquear()
    with pytest.raises(DiarioError):
        servico_com_alice.listar_notas()


def test_o_banco_guarda_apenas_texto_cifrado(servico_com_alice: DiarioService):
    """Contrato central do projeto, verificado direto na camada de dados."""
    servico = servico_com_alice
    servico.criar_nota("Título visível?", "Conteúdo confidencial do diário")

    for cifrada in servico.repositorio.listar_notas():
        assert "Título visível?" not in cifrada.title_cipher
        assert "Conteúdo confidencial" not in cifrada.content_cipher
        assert "confidencial" not in cifrada.content_cipher


def test_crud_completo(servico_com_alice: DiarioService):
    servico = servico_com_alice
    nota = servico.criar_nota("Rascunho", "primeira versão")
    assert nota.titulo == "Rascunho"

    atualizada = servico.atualizar_nota(nota.id, "Rascunho revisado", "segunda versão")
    assert atualizada.id == nota.id
    assert atualizada.conteudo == "segunda versão"

    servico.excluir_nota(nota.id)
    assert all(n.id != nota.id for n in servico.listar_notas())


def test_nota_sem_titulo_recebe_rotulo_padrao(servico_com_alice: DiarioService):
    nota = servico_com_alice.criar_nota("   ", "só conteúdo")
    assert nota.titulo == "Sem título"


def test_notas_vem_da_mais_recente_para_a_mais_antiga(servico_com_alice: DiarioService):
    servico = servico_com_alice
    servico.criar_nota("Segunda", "b")
    servico.criar_nota("Terceira", "c")
    datas = [n.created_at for n in servico.listar_notas()]
    assert datas == sorted(datas, reverse=True)


def test_busca_acontece_no_cliente(servico_com_alice: DiarioService):
    """Consequência da criptografia ponta a ponta: o filtro é local."""
    servico = servico_com_alice
    servico.criar_nota("Viagem a Florianópolis", "praia, sol e descanso")
    servico.criar_nota("Reunião de trabalho", "revisão do orçamento")

    assert len(servico.buscar("praia")) == 1
    assert len(servico.buscar("ORÇAMENTO")) == 1  # busca sem diferenciar caixa
    assert servico.buscar("inexistente") == []
    assert len(servico.buscar("")) == 3  # termo vazio devolve tudo


def test_troca_de_passphrase_mantem_as_notas_legiveis(servico_com_alice: DiarioService):
    servico = servico_com_alice
    antes = servico.listar_notas()[0]

    servico.trocar_passphrase(PASSPHRASE_ALICE, "nova-passphrase-longa")
    servico.bloquear()

    with pytest.raises(PassphraseIncorreta):
        servico.desbloquear(PASSPHRASE_ALICE)

    servico.desbloquear("nova-passphrase-longa")
    depois = servico.listar_notas()[0]
    assert depois.conteudo == antes.conteudo


def test_desbloquear_sem_cofre_criado(servico: DiarioService):
    servico.criar_conta("alice@exemplo.test", "senha-da-conta")
    with pytest.raises(CofreInexistente):
        servico.desbloquear("qualquer-coisa")


def test_email_duplicado_e_recusado(servico: DiarioService):
    servico.criar_conta("alice@exemplo.test", "senha-da-conta")
    servico.sair()
    with pytest.raises(AutenticacaoError):
        servico.criar_conta("alice@exemplo.test", "outra-senha")


def test_senha_errada_no_login(servico: DiarioService):
    servico.criar_conta("alice@exemplo.test", "senha-da-conta")
    servico.sair()
    with pytest.raises(AutenticacaoError):
        servico.entrar("alice@exemplo.test", "senha-errada")


def test_sair_bloqueia_o_cofre(servico_com_alice: DiarioService):
    servico = servico_com_alice
    servico.sair()
    assert not servico.cofre_aberto
    assert servico.sessao is None


def test_resumo_da_nota_trunca_a_primeira_linha(servico_com_alice: DiarioService):
    conteudo = "x" * 200 + "\nsegunda linha"
    nota = servico_com_alice.criar_nota("Longa", conteudo)
    assert nota.resumo.endswith("…")
    assert len(nota.resumo) == 81
