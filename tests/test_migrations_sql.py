"""Guarda-corpo das migrations.

Não substituem os testes pgTAP (que rodam SQL de verdade), mas pegam de graça
a classe de erro mais cara e mais silenciosa deste tipo de projeto: uma policy
removida, um ``enable row level security`` esquecido, um ``USING (true)``
colado de um tutorial. Qualquer um desses passa despercebido numa revisão e
abre o banco inteiro.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
PASTA_MIGRATIONS = RAIZ / "supabase" / "migrations"

TABELAS_PROTEGIDAS = ["public.notes", "public.diary_keys"]
OPERACOES = ["select", "insert", "update", "delete"]


def sql_completo() -> str:
    """Concatena as migrations em minúsculas e com espaçamento normalizado.

    A normalização evita que o teste quebre por alinhamento visual do SQL —
    o que interessa aqui é a regra, não a indentação.
    """
    arquivos = sorted(PASTA_MIGRATIONS.glob("*.sql"))
    assert arquivos, "Nenhuma migration encontrada em supabase/migrations/"
    bruto = "\n".join(a.read_text(encoding="utf-8").lower() for a in arquivos)
    return re.sub(r"[ \t\r\n]+", " ", bruto)


@pytest.fixture(scope="module")
def sql() -> str:
    return sql_completo()


@pytest.mark.parametrize("tabela", TABELAS_PROTEGIDAS)
def test_rls_habilitado_em_todas_as_tabelas(sql: str, tabela: str):
    assert f"alter table {tabela} enable row level security" in sql, (
        f"{tabela} não tem RLS habilitado — as policies seriam ignoradas."
    )


@pytest.mark.parametrize("tabela", TABELAS_PROTEGIDAS)
def test_rls_forcado_em_todas_as_tabelas(sql: str, tabela: str):
    assert f"alter table {tabela} force row level security" in sql, (
        f"{tabela} não tem FORCE RLS — o dono da tabela passaria por cima."
    )


@pytest.mark.parametrize("tabela", TABELAS_PROTEGIDAS)
def test_anon_nao_tem_privilegio(sql: str, tabela: str):
    assert f"revoke all on {tabela} from anon" in sql, (
        f"O papel anon ainda tem privilégios em {tabela}."
    )


@pytest.mark.parametrize("tabela", TABELAS_PROTEGIDAS)
@pytest.mark.parametrize("operacao", OPERACOES)
def test_existe_policy_para_cada_operacao(sql: str, tabela: str, operacao: str):
    nome_curto = tabela.split(".")[1]
    padrao = rf"create policy\s+\"{nome_curto}_{operacao}_proprias\"[\s\S]*?for {operacao}\b"
    assert re.search(padrao, sql), (
        f"Falta a policy de {operacao.upper()} em {tabela}."
    )


def test_todas_as_policies_comparam_auth_uid_com_user_id(sql: str):
    """Nenhuma policy pode liberar linha sem comparar o dono."""
    policies = re.findall(r"create policy[\s\S]*?;", sql)
    assert len(policies) == len(TABELAS_PROTEGIDAS) * len(OPERACOES)
    for policy in policies:
        assert "auth.uid()) = user_id" in policy, (
            f"Policy sem a comparação auth.uid() = user_id:\n{policy}"
        )


def test_nenhuma_policy_permissiva_demais(sql: str):
    """Caça o ``using (true)`` — o jeito mais fácil de anular o RLS."""
    for policy in re.findall(r"create policy[\s\S]*?;", sql):
        assert "using ( true )" not in policy
        assert "using (true)" not in policy
        assert "with check (true)" not in policy


def test_update_tem_using_e_with_check(sql: str):
    """Sem WITH CHECK, dá para transferir a própria linha para outro usuário."""
    for tabela in TABELAS_PROTEGIDAS:
        nome_curto = tabela.split(".")[1]
        trecho = re.search(
            rf"create policy\s+\"{nome_curto}_update_proprias\"[\s\S]*?;", sql
        )
        assert trecho, f"Policy de UPDATE ausente em {tabela}"
        corpo = trecho.group(0)
        assert "using" in corpo and "with check" in corpo


def test_policies_restritas_ao_papel_authenticated(sql: str):
    for policy in re.findall(r"create policy[\s\S]*?;", sql):
        assert "to authenticated" in policy, (
            f"Policy sem restrição de papel (deveria ser 'to authenticated'):\n{policy}"
        )


def test_auth_uid_envolvido_em_subquery(sql: str):
    """Boa prática de performance do Supabase: (select auth.uid()).

    Sem a subquery, a função é reavaliada linha a linha em vez de uma vez só.
    """
    for policy in re.findall(r"create policy[\s\S]*?;", sql):
        assert "(select auth.uid())" in policy


def test_indice_por_user_id_existe(sql: str):
    """Tabela com RLS sem índice em user_id vira sequential scan."""
    assert "notes_user_id_created_at_idx" in sql
    assert "on public.notes (user_id, created_at desc)" in sql


def test_view_usa_security_invoker(sql: str):
    """View sem security_invoker ignora o RLS da tabela de origem."""
    assert "security_invoker = on" in sql


def test_funcoes_com_search_path_travado(sql: str):
    """Toda função criada precisa fixar search_path (recomendação do Supabase)."""
    funcoes = re.findall(r"create or replace function[\s\S]*?\$\$;", sql)
    assert funcoes, "Nenhuma função encontrada nas migrations."
    for funcao in funcoes:
        assert "set search_path = ''" in funcao


def test_seed_existe_e_nao_usa_senha_de_producao():
    seed = (RAIZ / "supabase" / "seed.sql").read_text(encoding="utf-8")
    assert "nunca rode isto em produção" in seed.lower()
