-- =============================================================================
-- Migration: 20260731120100_rls_policies
-- Projeto  : Diário Pessoal Criptografado
-- Objetivo : Isolamento total por usuário via Row Level Security.
--
-- REGRA DE OURO DO PROJETO:
--     auth.uid() = user_id  para SELECT, INSERT, UPDATE e DELETE.
--
-- Modelo mental do RLS:
--   USING       -> filtra as linhas que a operação PODE ENXERGAR
--                  (SELECT, UPDATE, DELETE)
--   WITH CHECK  -> valida as linhas que a operação PODE GRAVAR
--                  (INSERT, UPDATE)
--
-- Por isso UPDATE precisa das duas cláusulas: USING impede editar nota alheia,
-- WITH CHECK impede transformar a minha nota em nota de outro (troca de
-- user_id). Só uma das duas deixa um buraco.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1. Ligar o RLS
--
-- Sem "enable row level security" as policies abaixo são decorativas: o
-- Postgres simplesmente as ignora e a tabela fica aberta para qualquer papel
-- com GRANT. Este é o erro nº 1 em projetos Supabase.
-- -----------------------------------------------------------------------------
alter table public.notes       enable row level security;
alter table public.diary_keys  enable row level security;

-- -----------------------------------------------------------------------------
-- 2. Privilégios de tabela (GRANT) — a camada ANTES do RLS
--
-- RLS filtra linhas; GRANT libera a operação. As duas camadas são
-- independentes e o pedido precisa passar pelas duas.
--
-- O papel "anon" (visitante sem login) não tem nada a fazer num diário
-- pessoal: revogamos tudo. Assim, um leak de policy jamais expõe o diário
-- para a internet — a requisição morre no GRANT, antes de chegar ao RLS.
-- -----------------------------------------------------------------------------
revoke all on public.notes      from anon;
revoke all on public.diary_keys from anon;

grant select, insert, update, delete on public.notes      to authenticated;
grant select, insert, update, delete on public.diary_keys to authenticated;

-- -----------------------------------------------------------------------------
-- 3. Policies de public.notes
--
-- Detalhe de performance: usamos (select auth.uid()) e não auth.uid() puro.
-- Envolvido em subquery, o planner avalia a função UMA vez (InitPlan) e
-- reaproveita o resultado; sem isso ela é reavaliada linha a linha. Em
-- tabelas grandes a diferença é de ordens de magnitude — é a recomendação
-- oficial de performance de RLS do Supabase.
-- -----------------------------------------------------------------------------

-- SELECT: leio apenas as minhas notas.
drop policy if exists "notes_select_proprias" on public.notes;
create policy "notes_select_proprias"
    on public.notes
    for select
    to authenticated
    using ( (select auth.uid()) = user_id );

-- INSERT: só consigo gravar linha em que eu sou o dono.
-- Combinado com o "default auth.uid()" da coluna, o cliente pode omitir
-- user_id; se tentar forjar outro valor, o WITH CHECK derruba o INSERT.
drop policy if exists "notes_insert_proprias" on public.notes;
create policy "notes_insert_proprias"
    on public.notes
    for insert
    to authenticated
    with check ( (select auth.uid()) = user_id );

-- UPDATE: USING = só alcanço as minhas linhas.
--         WITH CHECK = a linha resultante continua sendo minha.
drop policy if exists "notes_update_proprias" on public.notes;
create policy "notes_update_proprias"
    on public.notes
    for update
    to authenticated
    using      ( (select auth.uid()) = user_id )
    with check ( (select auth.uid()) = user_id );

-- DELETE: só apago o que é meu.
drop policy if exists "notes_delete_proprias" on public.notes;
create policy "notes_delete_proprias"
    on public.notes
    for delete
    to authenticated
    using ( (select auth.uid()) = user_id );

-- -----------------------------------------------------------------------------
-- 4. Policies de public.diary_keys
--
-- Mesmo princípio. Aqui o INSERT é feito uma única vez, na criação do cofre,
-- e o UPDATE só acontece na troca de passphrase (re-embrulho da DEK).
--
-- Vale reforçar: mesmo que um atacante conseguisse ler esta tabela inteira,
-- ele teria apenas salts públicos e DEKs cifradas — sem a passphrase do
-- usuário não há como abrir nenhuma nota. O RLS é a primeira barreira; a
-- criptografia no cliente é a segunda.
-- -----------------------------------------------------------------------------
drop policy if exists "diary_keys_select_proprias" on public.diary_keys;
create policy "diary_keys_select_proprias"
    on public.diary_keys
    for select
    to authenticated
    using ( (select auth.uid()) = user_id );

drop policy if exists "diary_keys_insert_proprias" on public.diary_keys;
create policy "diary_keys_insert_proprias"
    on public.diary_keys
    for insert
    to authenticated
    with check ( (select auth.uid()) = user_id );

drop policy if exists "diary_keys_update_proprias" on public.diary_keys;
create policy "diary_keys_update_proprias"
    on public.diary_keys
    for update
    to authenticated
    using      ( (select auth.uid()) = user_id )
    with check ( (select auth.uid()) = user_id );

drop policy if exists "diary_keys_delete_proprias" on public.diary_keys;
create policy "diary_keys_delete_proprias"
    on public.diary_keys
    for delete
    to authenticated
    using ( (select auth.uid()) = user_id );

-- -----------------------------------------------------------------------------
-- 5. Nota sobre o papel service_role
--
-- O service_role do Supabase tem o atributo BYPASSRLS: ele ignora TODAS as
-- policies acima. Isso é proposital (backups, jobs administrativos), mas
-- significa que a service_role key JAMAIS pode ir para o cliente — nem para
-- o navegador, nem para o app Streamlit, nem para variável de ambiente
-- versionada. Ver docs/SEGURANCA_E_CRIPTOGRAFIA.md, seção "Chaves".
-- -----------------------------------------------------------------------------
