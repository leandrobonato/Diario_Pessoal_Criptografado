"""Teste de ponta a ponta da interface, sem navegador.

Usa o ``AppTest`` do próprio Streamlit: ele executa ``app.py`` no processo do
teste, deixa preencher widgets e clicar botões, e expõe o que foi renderizado.
Cobre o caminho que o usuário realmente percorre — cadastro → criação do cofre
→ escrita de uma nota — e confere, ao final, que o que chegou à camada de
dados está cifrado.

Todos os botões e campos do app têm ``key`` explícita justamente para que este
teste selecione elementos por identidade, não por posição na tela.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

RAIZ = Path(__file__).resolve().parents[1]
APP = RAIZ / "app.py"

PASSPHRASE = "cafe-com-leite-42"


@pytest.fixture()
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AppTest:
    """Sobe o app em modo demonstração, com banco descartável."""
    monkeypatch.setenv("DIARIO_BACKEND", "local")
    monkeypatch.setenv("DIARIO_DB_PATH", str(tmp_path / "app_teste.db"))
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_ANON_KEY", raising=False)
    return AppTest.from_file(str(APP), default_timeout=60)


def _erros(at: AppTest) -> list[str]:
    return [e.value for e in at.error]


def _subtitulos(at: AppTest) -> str:
    return "\n".join(s.value for s in at.subheader)


def _criar_conta(at: AppTest) -> AppTest:
    at.text_input(key="cadastro_email").set_value("alice@exemplo.test")
    at.text_input(key="cadastro_senha").set_value("senha-da-conta")
    return at.button(key="btn_criar_conta").click().run()


def _criar_cofre(at: AppTest, passphrase: str = PASSPHRASE, repetida: str | None = None) -> AppTest:
    at.text_input(key="cofre_nova").set_value(passphrase)
    at.text_input(key="cofre_nova_repetida").set_value(
        repetida if repetida is not None else passphrase
    )
    return at.button(key="btn_criar_cofre").click().run()


def test_tela_inicial_pede_autenticacao(app: AppTest):
    at = app.run()
    assert not at.exception
    assert at.text_input(key="login_email") is not None
    assert at.button(key="btn_entrar") is not None


def test_cadastro_leva_a_criacao_do_cofre(app: AppTest):
    at = _criar_conta(app.run())
    assert not at.exception
    assert "Defina a passphrase do seu diário" in _subtitulos(at)


def test_fluxo_completo_ate_escrever_uma_nota(app: AppTest):
    at = _criar_cofre(_criar_conta(app.run()))
    assert not at.exception

    at.text_input(key="editor_titulo").set_value("Primeiro dia")
    at.text_area(key="editor_conteudo").set_value("Hoje comecei um diário cifrado.")
    at = at.button(key="btn_salvar").click().run()
    assert not at.exception
    assert not _erros(at)

    servico = at.session_state["servico"]
    assert [n.titulo for n in servico.listar_notas()] == ["Primeiro dia"]

    # E o que existe na camada de dados continua opaco.
    cifrada = servico.repositorio.listar_notas()[0]
    assert "Primeiro dia" not in cifrada.title_cipher
    assert "diário cifrado" not in cifrada.content_cipher


def test_bloquear_e_desbloquear_o_cofre(app: AppTest):
    at = _criar_cofre(_criar_conta(app.run()))

    at = at.button(key="btn_bloquear").click().run()
    assert "Desbloqueie o seu diário" in _subtitulos(at)

    at.text_input(key="cofre_desbloqueio").set_value("passphrase-errada")
    at = at.button(key="btn_desbloquear").click().run()
    assert any("incorreta" in e.lower() for e in _erros(at))

    at.text_input(key="cofre_desbloqueio").set_value(PASSPHRASE)
    at = at.button(key="btn_desbloquear").click().run()
    assert at.session_state["servico"].cofre_aberto


def test_passphrases_diferentes_sao_recusadas(app: AppTest):
    at = _criar_cofre(_criar_conta(app.run()), repetida="outra-coisa-completamente")
    assert "As passphrases não conferem." in _erros(at)


def test_barra_lateral_mostra_o_user_id(app: AppTest):
    """O user_id da sidebar é o valor que o RLS compara com notes.user_id."""
    at = _criar_conta(app.run())
    servico = at.session_state["servico"]
    legendas = "\n".join(c.value for c in at.sidebar.caption)
    assert servico.sessao is not None
    assert servico.sessao.user_id in legendas


def test_modo_demonstracao_e_sinalizado(app: AppTest):
    at = app.run()
    avisos = "\n".join(w.value for w in at.warning)
    assert "Modo demonstração" in avisos
