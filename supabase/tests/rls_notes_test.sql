-- =============================================================================
-- Testes de RLS (pgTAP) — Diário Pessoal Criptografado
--
-- Como rodar (exige Supabase CLI + Docker):
--     supabase start
--     supabase test db
--
-- Estratégia: em vez de confiar na leitura das policies, o teste ENCARNA dois
-- usuários reais dentro de uma transação, alternando o papel do Postgres e as
-- claims do JWT — exatamente o que o PostgREST faz a cada requisição:
--
--     set local request.jwt.claims = '{"sub": "<uuid>", "role": "authenticated"}';
--     set local role authenticated;
--
-- A partir daí, auth.uid() devolve o "sub" do JWT e as policies entram em ação.
-- Tudo roda dentro de begin/rollback: o banco volta ao estado anterior.
-- =============================================================================

begin;

create extension if not exists pgtap with schema extensions;

select plan(18);

-- -----------------------------------------------------------------------------
-- Massa de teste: dois usuários no auth.users
-- -----------------------------------------------------------------------------
insert into auth.users (id, email, aud, role, raw_app_meta_data, raw_user_meta_data, created_at, updated_at)
values
    ('11111111-1111-1111-1111-111111111111', 'alice@exemplo.test', 'authenticated', 'authenticated', '{}', '{}', now(), now()),
    ('22222222-2222-2222-2222-222222222222', 'bruno@exemplo.test', 'authenticated', 'authenticated', '{}', '{}', now(), now());

-- =============================================================================
-- BLOCO 1 — Estrutura: as tabelas existem e o RLS está de fato ligado
-- =============================================================================

-- 1
select has_table('public', 'notes', 'A tabela public.notes existe');

-- 2
select has_table('public', 'diary_keys', 'A tabela public.diary_keys existe');

-- 3
select ok(
    (select relrowsecurity from pg_class where oid = 'public.notes'::regclass),
    'RLS está HABILITADO em public.notes'
);

-- 4
select ok(
    (select relforcerowsecurity from pg_class where oid = 'public.notes'::regclass),
    'RLS está FORÇADO em public.notes (vale inclusive para o dono da tabela)'
);

-- 5
select policies_are(
    'public', 'notes',
    array[
        'notes_select_proprias',
        'notes_insert_proprias',
        'notes_update_proprias',
        'notes_delete_proprias'
    ],
    'public.notes tem exatamente as 4 policies esperadas (SELECT/INSERT/UPDATE/DELETE)'
);

-- 6
select policies_are(
    'public', 'diary_keys',
    array[
        'diary_keys_select_proprias',
        'diary_keys_insert_proprias',
        'diary_keys_update_proprias',
        'diary_keys_delete_proprias'
    ],
    'public.diary_keys tem exatamente as 4 policies esperadas'
);

-- =============================================================================
-- BLOCO 2 — Alice cria o seu cofre e a sua nota
-- =============================================================================
set local request.jwt.claims = '{"sub": "11111111-1111-1111-1111-111111111111", "role": "authenticated"}';
set local role authenticated;

insert into public.diary_keys (kdf_salt, wrapped_dek)
values ('c2FsdC1hbGljZS0xMjM0NTY3OA==', 'ZW52ZWxvcGUtZGVrLWFsaWNlLWNpZnJhZGEtYmFzZTY0LWV4ZW1wbG8=');

insert into public.notes (id, title_cipher, content_cipher)
values (
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    'dGl0dWxvLWNpZnJhZG8tZGEtYWxpY2UtYmFzZTY0LWV4ZW1wbG8=',
    'Y29udGV1ZG8tY2lmcmFkby1kYS1hbGljZS1iYXNlNjQtZXhlbXBsbw=='
);

-- 7
select is(
    (select user_id from public.notes where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    '11111111-1111-1111-1111-111111111111'::uuid,
    'INSERT sem informar user_id herda auth.uid() pelo DEFAULT da coluna'
);

-- 8
select is(
    (select count(*) from public.notes),
    1::bigint,
    'Alice enxerga exatamente 1 nota (a sua)'
);

-- =============================================================================
-- BLOCO 3 — Bruno entra em cena: o isolamento precisa ser total
-- =============================================================================
reset role;
set local request.jwt.claims = '{"sub": "22222222-2222-2222-2222-222222222222", "role": "authenticated"}';
set local role authenticated;

insert into public.diary_keys (kdf_salt, wrapped_dek)
values ('c2FsdC1icnVuby0xMjM0NTY3OA==', 'ZW52ZWxvcGUtZGVrLWJydW5vLWNpZnJhZGEtYmFzZTY0LWV4ZW1wbG8=');

insert into public.notes (id, title_cipher, content_cipher)
values (
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'dGl0dWxvLWNpZnJhZG8tZG8tYnJ1bm8tYmFzZTY0LWV4ZW1wbG8=',
    'Y29udGV1ZG8tY2lmcmFkby1kby1icnVuby1iYXNlNjQtZXhlbXBsbw=='
);

-- 9
select is(
    (select count(*) from public.notes),
    1::bigint,
    'SELECT: Bruno enxerga 1 nota — a nota da Alice é invisível para ele'
);

-- 10
select is(
    (select count(*) from public.notes where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    0::bigint,
    'SELECT direto pelo id da nota da Alice não retorna nada (RLS filtra antes do WHERE)'
);

-- 11
select is(
    (with tentativa as (
        update public.notes
           set content_cipher = 'aW52YXNhby1kZS1jb250ZXVkby1wZWxvLWJydW5vLWJhc2U2NC1leGVtcGxv'
         where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        returning 1
    ) select count(*) from tentativa),
    0::bigint,
    'UPDATE na nota da Alice afeta 0 linhas (USING da policy de UPDATE)'
);

-- 12
select is(
    (with tentativa as (
        delete from public.notes
         where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        returning 1
    ) select count(*) from tentativa),
    0::bigint,
    'DELETE na nota da Alice afeta 0 linhas (USING da policy de DELETE)'
);

-- 13
select throws_ok(
    $$
        insert into public.notes (user_id, title_cipher, content_cipher)
        values (
            '11111111-1111-1111-1111-111111111111',
            'dGl0dWxvLWZvcmphZG8tcGVsby1icnVuby1iYXNlNjQtZXhlbXBsbw==',
            'Y29udGV1ZG8tZm9yamFkby1wZWxvLWJydW5vLWJhc2U2NC1leGVtcGxv'
        )
    $$,
    '42501',
    'new row violates row-level security policy for table "notes"',
    'INSERT forjando user_id alheio é bloqueado pelo WITH CHECK'
);

-- 14
select is(
    (select count(*) from public.diary_keys),
    1::bigint,
    'O cofre de chaves também é isolado: Bruno só vê a própria linha'
);

-- 15
select is(
    public.contar_minhas_notas(),
    1::bigint,
    'A função contar_minhas_notas() (security invoker) respeita o RLS'
);

-- 16
select is(
    (select coalesce(sum(total_notas), 0) from public.minhas_notas_por_mes),
    1::bigint,
    'A view minhas_notas_por_mes (security_invoker = on) agrega apenas as notas do usuário logado'
);

-- =============================================================================
-- BLOCO 4 — Visitante anônimo e integridade final
-- =============================================================================
reset role;
set local role anon;

-- 17
select throws_ok(
    'select count(*) from public.notes',
    '42501',
    'permission denied for table notes',
    'O papel anon nem chega ao RLS: o GRANT já barra o acesso à tabela'
);

reset role;
set local request.jwt.claims = '{"sub": "11111111-1111-1111-1111-111111111111", "role": "authenticated"}';
set local role authenticated;

-- 18
select is(
    (select content_cipher from public.notes where id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
    'Y29udGV1ZG8tY2lmcmFkby1kYS1hbGljZS1iYXNlNjQtZXhlbXBsbw==',
    'A nota da Alice permanece intacta após todas as tentativas do Bruno'
);

reset role;

select * from finish();

rollback;
