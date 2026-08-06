-- =============================================================================
-- Migration: 20260731120200_hardening_e_visoes
-- Projeto  : Diário Pessoal Criptografado
-- Objetivo : Endurecer o RLS e expor uma visão agregada que RESPEITA o RLS.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. FORCE ROW LEVEL SECURITY
--
-- "enable row level security" não vale para o DONO da tabela: por padrão o
-- owner (no Supabase, o papel postgres) passa por cima das policies. Com
-- "force", nem o dono escapa — as policies valem para todo mundo que não
-- tenha o atributo BYPASSRLS.
--
-- Efeito prático:
--   * o app (papel authenticated) continua igual;
--   * o service_role continua enxergando tudo (tem BYPASSRLS) — é o caminho
--     legítimo para backup/manutenção;
--   * scripts administrativos rodando como owner passam a respeitar o RLS,
--     o que evita o clássico "rodei um UPDATE sem WHERE no SQL Editor".
--
-- Para desligar durante uma manutenção pesada:
--     alter table public.notes no force row level security;
-- -----------------------------------------------------------------------------
alter table public.notes      force row level security;
alter table public.diary_keys force row level security;

-- -----------------------------------------------------------------------------
-- 2. Visão agregada: quantas notas escrevi por mês
--
-- ARMADILHA CLÁSSICA: uma view no PostgreSQL é executada, por padrão, com os
-- privilégios de QUEM A CRIOU (security definer). Isso significa que uma view
-- criada pelo postgres sobre uma tabela com RLS entregaria as linhas de TODOS
-- os usuários — um vazamento silencioso, com o RLS ligado e aparentemente
-- funcionando.
--
-- "with (security_invoker = on)" (PostgreSQL 15+) inverte isso: a view roda
-- com os privilégios de quem CONSULTA, e as policies de public.notes são
-- aplicadas normalmente. Cada usuário vê apenas o agregado do próprio diário.
-- -----------------------------------------------------------------------------
create or replace view public.minhas_notas_por_mes
with (security_invoker = on)
as
select
    date_trunc('month', created_at)::date as mes,
    count(*)                              as total_notas,
    min(created_at)                       as primeira_nota,
    max(created_at)                       as ultima_nota
from public.notes
group by 1
order by 1 desc;

comment on view public.minhas_notas_por_mes is
    'Notas por mês do usuário logado. security_invoker = on garante que o RLS de public.notes seja aplicado.';

revoke all on public.minhas_notas_por_mes from anon;
grant select on public.minhas_notas_por_mes to authenticated;

-- -----------------------------------------------------------------------------
-- 3. Função de diagnóstico (usada pelos testes e pelo app)
--
-- Retorna o que o RLS enxerga a partir da sessão atual. É deliberadamente
-- SECURITY INVOKER: se fosse SECURITY DEFINER, devolveria a contagem global e
-- viraria um canal de vazamento.
-- -----------------------------------------------------------------------------
create or replace function public.contar_minhas_notas()
returns bigint
language sql
stable
security invoker
set search_path = ''
as $$
    select count(*) from public.notes;
$$;

comment on function public.contar_minhas_notas() is
    'Conta as notas visíveis pelo RLS para a sessão atual. security invoker por design.';

revoke all on function public.contar_minhas_notas() from anon;
grant execute on function public.contar_minhas_notas() to authenticated;
