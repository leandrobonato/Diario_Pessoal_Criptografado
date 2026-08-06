"""Diário Pessoal Criptografado — interface Streamlit.

Rodar:

    streamlit run app.py

A tela é fina de propósito: toda a lógica vive em :mod:`diario.service`. Aqui
só existe apresentação, estado de sessão e tradução de exceção em mensagem.
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# Permite `streamlit run app.py` sem instalar o pacote (útil para quem só quer
# ver o projeto rodando). Em uso normal, `pip install -e .` também funciona.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from diario.config import alerta_de_chave_de_servico, carregar_configuracao  # noqa: E402
from diario.errors import (  # noqa: E402
    AcessoNegado,
    AutenticacaoError,
    BackendIndisponivel,
    CofreJaExiste,
    DiarioError,
    PassphraseIncorreta,
)
from diario.repository import criar_repositorio  # noqa: E402
from diario.service import DiarioService  # noqa: E402

st.set_page_config(
    page_title="Diário Pessoal Criptografado",
    page_icon="🔐",
    layout="wide",
)


# --------------------------------------------------------------------------- #
# Estado
# --------------------------------------------------------------------------- #
def obter_servico() -> DiarioService | None:
    """Cria (uma vez por sessão do navegador) o serviço do diário."""
    if "servico" in st.session_state:
        return st.session_state["servico"]
    try:
        cfg = carregar_configuracao()
        st.session_state["config"] = cfg
        st.session_state["servico"] = DiarioService(criar_repositorio(cfg))
    except BackendIndisponivel as exc:
        st.error(f"Backend indisponível: {exc}")
        return None
    except Exception as exc:  # configuração inválida
        st.error(f"Falha ao iniciar o diário: {exc}")
        return None
    return st.session_state["servico"]


#: Campos da interface e seus valores iniciais. Declarar tudo num lugar só
#: evita ``KeyError`` quando uma tela some do fluxo (o Streamlit descarta o
#: estado de widgets que deixaram de ser renderizados) e deixa o app
#: inspecionável por testes que selecionam elementos pela ``key``.
ESTADO_INICIAL: dict[str, object] = {
    "login_email": "",
    "login_senha": "",
    "cadastro_email": "",
    "cadastro_senha": "",
    "cofre_nova": "",
    "cofre_nova_repetida": "",
    "cofre_desbloqueio": "",
    "troca_atual": "",
    "troca_nova": "",
    "troca_confirma": "",
    "editor_titulo": "",
    "editor_conteudo": "",
    "busca": "",
    "isolamento_id": "",
    "nota_selecionada": None,
}


def inicializar_estado() -> None:
    for chave, padrao in ESTADO_INICIAL.items():
        st.session_state.setdefault(chave, padrao)


def recarregar() -> None:
    st.rerun()


def _agendar_editor(nota_id: str | None, titulo: str = "", conteudo: str = "") -> None:
    """Agenda o conteúdo que o editor deve exibir no próximo rerun.

    Dois detalhes do Streamlit obrigam esse rodeio:

    1. um widget com ``key`` guarda o próprio valor entre reruns e ignora o
       parâmetro ``value`` a partir da segunda renderização — para trocar o que
       aparece, é preciso escrever na chave do widget no ``session_state``;
    2. escrever nessa chave **depois** que o widget já foi criado no mesmo run
       levanta ``StreamlitAPIException``.

    Guardando a intenção numa chave própria e aplicando-a no início do run
    seguinte (:func:`_aplicar_pendencia_do_editor`), os dois problemas somem.
    """
    st.session_state["_editor_pendente"] = (nota_id, titulo, conteudo)


def _limpar_editor() -> None:
    _agendar_editor(None)


def _aplicar_pendencia_do_editor() -> None:
    """Aplica o agendamento antes de qualquer widget do editor ser criado."""
    pendente = st.session_state.pop("_editor_pendente", None)
    if pendente is None:
        return
    nota_id, titulo, conteudo = pendente
    st.session_state["nota_selecionada"] = nota_id
    st.session_state["editor_titulo"] = titulo
    st.session_state["editor_conteudo"] = conteudo


# --------------------------------------------------------------------------- #
# Blocos de interface
# --------------------------------------------------------------------------- #
def cabecalho(servico: DiarioService) -> None:
    cfg = st.session_state.get("config")
    modo = servico.repositorio.nome

    st.title("🔐 Diário Pessoal Criptografado")
    coluna_texto, coluna_modo = st.columns([3, 1])
    with coluna_texto:
        st.caption(
            "Suas anotações são cifradas **antes** de sair daqui e isoladas por "
            "usuário no banco via Row Level Security."
        )
    with coluna_modo:
        if cfg and cfg.usa_supabase:
            st.success(f"Backend: {modo}", icon="🛡️")
        else:
            st.info(f"Backend: {modo}", icon="🧪")

    aviso = alerta_de_chave_de_servico()
    if aviso:
        st.error(aviso, icon="🚨")


def barra_lateral(servico: DiarioService) -> None:
    with st.sidebar:
        st.header("Sessão")
        sessao = servico.sessao
        if sessao:
            st.write(f"**{sessao.email}**")
            st.caption(f"user_id: `{sessao.user_id}`")
            st.caption(
                "Este é o `auth.uid()` que as policies comparam com "
                "`notes.user_id`."
            )
            if servico.cofre_aberto:
                if st.button("🔒 Bloquear cofre", key="btn_bloquear", use_container_width=True):
                    servico.bloquear()
                    recarregar()
            if st.button("Sair", key="btn_sair", use_container_width=True):
                servico.sair()
                _limpar_editor()
                recarregar()
        else:
            st.caption("Nenhum usuário autenticado.")

        st.divider()
        cfg = st.session_state.get("config")
        if cfg and not cfg.usa_supabase:
            st.warning(
                "**Modo demonstração**\n\nOs dados ficam num SQLite local "
                "(`data/diario_demo.db`) e o isolamento é reproduzido na "
                "aplicação. Para exercitar o RLS de verdade, configure o "
                "`.env` com um projeto Supabase.",
                icon="🧪",
            )


def tela_autenticacao(servico: DiarioService) -> None:
    aba_entrar, aba_criar = st.tabs(["Entrar", "Criar conta"])

    with aba_entrar:
        with st.form("form_entrar"):
            email = st.text_input("E-mail", key="login_email")
            senha = st.text_input("Senha da conta", type="password", key="login_senha")
            if st.form_submit_button("Entrar", key="btn_entrar", type="primary"):
                try:
                    servico.entrar(email, senha)
                    recarregar()
                except AutenticacaoError as exc:
                    st.error(str(exc))

    with aba_criar:
        st.caption(
            "A senha da **conta** autentica você no Supabase. A passphrase do "
            "**diário**, pedida no próximo passo, é outra coisa: ela nunca sai "
            "deste dispositivo e é a única capaz de abrir suas notas."
        )
        with st.form("form_criar"):
            email = st.text_input("E-mail", key="cadastro_email")
            senha = st.text_input("Senha da conta", type="password", key="cadastro_senha")
            if st.form_submit_button("Criar conta", key="btn_criar_conta", type="primary"):
                try:
                    servico.criar_conta(email, senha)
                    recarregar()
                except AutenticacaoError as exc:
                    st.error(str(exc))


def tela_cofre(servico: DiarioService) -> None:
    status = servico.status_do_cofre()

    if status == "inexistente":
        st.subheader("Defina a passphrase do seu diário")
        st.warning(
            "**Não há recuperação.** A passphrase nunca é enviada ao servidor: "
            "é ela que deriva a chave que abre suas notas. Se você esquecê-la, "
            "o conteúdo é matematicamente irrecuperável — nem você, nem eu, nem "
            "o administrador do banco.",
            icon="⚠️",
        )
        with st.form("form_criar_cofre"):
            p1 = st.text_input("Passphrase do diário", type="password", key="cofre_nova")
            p2 = st.text_input("Repita a passphrase", type="password", key="cofre_nova_repetida")
            if st.form_submit_button("Criar cofre", key="btn_criar_cofre", type="primary"):
                if p1 != p2:
                    st.error("As passphrases não conferem.")
                else:
                    try:
                        servico.criar_cofre(p1)
                        recarregar()
                    except (ValueError, CofreJaExiste, DiarioError) as exc:
                        st.error(str(exc))
        return

    st.subheader("Desbloqueie o seu diário")
    st.caption(
        "A chave é derivada com Scrypt na sua máquina — a demora de alguns "
        "décimos de segundo é intencional: é o que encarece ataque de força bruta."
    )
    with st.form("form_desbloquear"):
        passphrase = st.text_input("Passphrase do diário", type="password", key="cofre_desbloqueio")
        if st.form_submit_button("Desbloquear", key="btn_desbloquear", type="primary"):
            try:
                servico.desbloquear(passphrase)
                recarregar()
            except PassphraseIncorreta as exc:
                st.error(str(exc))
            except DiarioError as exc:
                st.error(str(exc))


def tela_diario(servico: DiarioService) -> None:
    aba_notas, aba_isolamento, aba_seguranca = st.tabs(
        ["📓 Minhas notas", "🛡️ Prova de isolamento", "🔑 Segurança"]
    )

    with aba_notas:
        _aba_notas(servico)
    with aba_isolamento:
        _aba_isolamento(servico)
    with aba_seguranca:
        _aba_seguranca(servico)


def _aba_notas(servico: DiarioService) -> None:
    termo = st.text_input(
        "Buscar", placeholder="filtrar por título ou conteúdo…", key="busca"
    )
    try:
        notas = servico.buscar(termo)
    except DiarioError as exc:
        st.error(str(exc))
        return

    coluna_lista, coluna_editor = st.columns([1, 2], gap="large")

    with coluna_lista:
        st.caption(f"{len(notas)} nota(s)")
        if st.button("➕ Nova nota", key="btn_nova_nota", use_container_width=True, type="primary"):
            _limpar_editor()
            recarregar()

        for nota in notas:
            rotulo = f"**{nota.titulo}**\n\n{nota.created_at:%d/%m/%Y %H:%M}"
            if st.button(rotulo, key=f"sel_{nota.id}", use_container_width=True):
                _agendar_editor(nota.id, nota.titulo, nota.conteudo)
                recarregar()

    with coluna_editor:
        selecionada = st.session_state.get("nota_selecionada")
        st.subheader("Editar nota" if selecionada else "Nova nota")

        titulo = st.text_input("Título", key="editor_titulo")
        conteudo = st.text_area("Como foi o seu dia?", height=320, key="editor_conteudo")

        botoes = st.columns(3)
        with botoes[0]:
            if st.button("💾 Salvar", key="btn_salvar", type="primary", use_container_width=True):
                try:
                    if selecionada:
                        salva = servico.atualizar_nota(selecionada, titulo, conteudo)
                    else:
                        salva = servico.criar_nota(titulo, conteudo)
                    _agendar_editor(salva.id, salva.titulo, salva.conteudo)
                    st.toast("Nota cifrada e salva.", icon="🔐")
                    recarregar()
                except (AcessoNegado, DiarioError) as exc:
                    st.error(str(exc))
        with botoes[1]:
            if selecionada and st.button("🗑️ Excluir", key="btn_excluir", use_container_width=True):
                try:
                    servico.excluir_nota(selecionada)
                    _limpar_editor()
                    recarregar()
                except (AcessoNegado, DiarioError) as exc:
                    st.error(str(exc))
        with botoes[2]:
            if st.button("✖️ Limpar", key="btn_limpar", use_container_width=True):
                _limpar_editor()
                recarregar()

        if selecionada:
            with st.expander("Ver o que o servidor guarda desta nota"):
                cifrada = servico.repositorio.tentar_ler_nota(selecionada)
                if cifrada:
                    st.caption("`notes.title_cipher`")
                    st.code(cifrada.title_cipher, language=None)
                    st.caption("`notes.content_cipher`")
                    st.code(cifrada.content_cipher, language=None)
                    st.caption(
                        "É exatamente isto que existe no banco: Base64 de "
                        "`nonce ‖ ciphertext ‖ tag` (AES-256-GCM). Sem a sua "
                        "passphrase, esses bytes não viram texto."
                    )


def _aba_isolamento(servico: DiarioService) -> None:
    st.subheader("O usuário só alcança as próprias linhas")
    st.markdown(
        """
A regra que sustenta este projeto é uma linha de SQL, repetida nas quatro
operações:

```sql
using ( (select auth.uid()) = user_id )   -- SELECT, UPDATE, DELETE
with check ( (select auth.uid()) = user_id )  -- INSERT, UPDATE
```

Abaixo você pode tentar quebrá-la. Pegue o id de uma nota **de outro usuário**
(crie uma segunda conta em outra janela anônima) e cole aqui.
"""
    )

    nota_id = st.text_input("id da nota (uuid)", key="isolamento_id")
    if st.button("Tentar ler esta nota", key="btn_tentar_ler"):
        try:
            nota = servico.tentar_ler_nota_por_id(nota_id.strip())
        except DiarioError as exc:
            st.error(str(exc))
        else:
            if nota is None:
                st.success(
                    "Nada retornado. Se o id existe e é de outro usuário, foi a "
                    "policy de SELECT que o filtrou — a consulta nem chegou a "
                    "enxergar a linha.",
                    icon="🛡️",
                )
            else:
                st.info(f"Retornou uma nota sua: **{nota.titulo}**")

    st.divider()
    repositorio = servico.repositorio
    if hasattr(repositorio, "contar_notas_no_banco"):
        total_no_banco = repositorio.contar_notas_no_banco()
        try:
            visiveis = len(servico.listar_notas())
        except DiarioError:
            visiveis = 0
        col_a, col_b = st.columns(2)
        col_a.metric("Linhas na tabela `notes` (todas as contas)", total_no_banco)
        col_b.metric("Linhas que a sua sessão enxerga", visiveis)
        st.caption(
            "A primeira contagem ignora a política de propósito, só para a "
            "demonstração. A segunda é o que o usuário realmente alcança."
        )
    else:
        st.caption(
            "No backend Supabase a contagem global simplesmente não existe para "
            "o usuário: `select count(*) from notes` já volta filtrado pelo RLS. "
            "Para conferir do lado do servidor, rode `python scripts/verificar_rls.py`."
        )


def _aba_seguranca(servico: DiarioService) -> None:
    st.subheader("Trocar a passphrase do diário")
    st.caption(
        "A troca é instantânea mesmo com milhares de notas: apenas o envelope "
        "da chave de dados (DEK) é refeito — nenhuma nota é reescrita."
    )
    with st.form("form_trocar_passphrase"):
        atual = st.text_input("Passphrase atual", type="password", key="troca_atual")
        nova = st.text_input("Nova passphrase", type="password", key="troca_nova")
        confirma = st.text_input("Repita a nova passphrase", type="password", key="troca_confirma")
        if st.form_submit_button("Trocar passphrase", key="btn_trocar_passphrase", type="primary"):
            if nova != confirma:
                st.error("As passphrases não conferem.")
            else:
                try:
                    servico.trocar_passphrase(atual, nova)
                    st.success("Passphrase trocada. Suas notas continuam intactas.")
                except (PassphraseIncorreta, ValueError, DiarioError) as exc:
                    st.error(str(exc))

    st.divider()
    st.markdown(
        """
**Como as chaves se encaixam**

| Camada | O que protege | Onde vive |
|---|---|---|
| Senha da conta | autenticação (Supabase Auth) | servidor, com hash |
| Passphrase do diário | deriva a KEK via Scrypt | só na sua cabeça |
| KEK | embrulha a DEK | memória do cliente |
| DEK (256 bits aleatórios) | cifra título e conteúdo | memória do cliente; no banco só embrulhada |
| RLS (`auth.uid() = user_id`) | isola as linhas por usuário | PostgreSQL |

Duas barreiras independentes: mesmo que o RLS falhasse, o invasor levaria
bytes cifrados. Mesmo que a criptografia fosse quebrada, o RLS não teria
entregue as linhas.
"""
    )


# --------------------------------------------------------------------------- #
# Fluxo principal
# --------------------------------------------------------------------------- #
def main() -> None:
    servico = obter_servico()
    if servico is None:
        st.stop()

    inicializar_estado()
    _aplicar_pendencia_do_editor()
    cabecalho(servico)
    barra_lateral(servico)

    if not servico.logado:
        tela_autenticacao(servico)
    elif not servico.cofre_aberto:
        tela_cofre(servico)
    else:
        tela_diario(servico)


main()
