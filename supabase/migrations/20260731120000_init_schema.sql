-- =============================================================================
-- Migration: 20260731120000_init_schema
-- Projeto  : Diário Pessoal Criptografado
-- Objetivo : Criar o schema base do diário (cofre de chaves + notas cifradas).
--
-- Princípio de projeto: o banco NUNCA vê texto em claro. Todo conteúdo sensível
-- chega aqui como envelope AES-256-GCM em Base64, cifrado no cliente. O banco
-- é responsável apenas por (a) guardar os bytes e (b) garantir, via RLS, que
-- cada linha só é visível para o seu dono.
-- =============================================================================

-- gen_random_uuid() é nativo do PostgreSQL desde a versão 13 (o Supabase roda
-- 15+), então não há dependência de pgcrypto aqui — uma extensão a menos para
-- instalar e uma migration que também roda em Postgres puro.

-- -----------------------------------------------------------------------------
-- Tabela: public.diary_keys
-- Cofre de chaves por usuário (um registro por usuário).
--
-- Fluxo de chaves (detalhado em docs/SEGURANCA_E_CRIPTOGRAFIA.md):
--   passphrase do diário --Scrypt(kdf_salt)--> KEK (nunca sai do cliente)
--   DEK aleatória de 32 bytes --AES-GCM(KEK)--> wrapped_dek (guardado aqui)
--   notas --AES-GCM(DEK)--> title_cipher / content_cipher
--
-- Guardar a DEK "embrulhada" pela KEK permite trocar a passphrase sem
-- reescrever nenhuma nota: basta re-embrulhar a mesma DEK.
-- -----------------------------------------------------------------------------
create table if not exists public.diary_keys (
    user_id     uuid primary key
                references auth.users (id) on delete cascade
                default auth.uid(),

    -- Salt aleatório do Scrypt, em Base64 (16 bytes). Público por definição.
    kdf_salt    text        not null,

    -- Parâmetros do KDF gravados junto com o salt: permitem endurecer o custo
    -- no futuro sem invalidar cofres antigos (cada usuário carrega o seu).
    kdf_params  jsonb       not null
                default '{"algorithm": "scrypt", "n": 32768, "r": 8, "p": 1, "length": 32}'::jsonb,

    -- DEK cifrada com a KEK: Base64 de (nonce ‖ ciphertext ‖ tag).
    wrapped_dek text        not null,

    -- Versão do envelope criptográfico, para migração de formato no futuro.
    crypto_version smallint not null default 1,

    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),

    constraint diary_keys_kdf_salt_nao_vazio    check (length(kdf_salt) >= 16),
    constraint diary_keys_wrapped_dek_nao_vazio check (length(wrapped_dek) >= 32),
    constraint diary_keys_crypto_version_valida check (crypto_version >= 1)
);

comment on table  public.diary_keys is
    'Cofre de chaves por usuário: salt do KDF e DEK embrulhada. Nenhum segredo em claro.';
comment on column public.diary_keys.wrapped_dek is
    'Base64(nonce ‖ ciphertext ‖ tag) da DEK cifrada com a KEK derivada da passphrase.';

-- -----------------------------------------------------------------------------
-- Tabela: public.notes
-- As anotações do diário. Título e conteúdo são opacos para o servidor.
-- -----------------------------------------------------------------------------
create table if not exists public.notes (
    id             uuid        primary key default gen_random_uuid(),

    -- default auth.uid(): o cliente não precisa (nem deve) informar o dono.
    -- Combinado com a policy WITH CHECK, torna impossível gravar nota alheia.
    user_id        uuid        not null
                   references auth.users (id) on delete cascade
                   default auth.uid(),

    title_cipher   text        not null,
    content_cipher text        not null,

    crypto_version smallint    not null default 1,

    created_at     timestamptz not null default now(),
    updated_at     timestamptz not null default now(),

    constraint notes_title_cipher_nao_vazio   check (length(title_cipher)   >= 32),
    constraint notes_content_cipher_nao_vazio check (length(content_cipher) >= 32),
    constraint notes_crypto_version_valida    check (crypto_version >= 1),

    -- Trava de tamanho: evita que a tabela vire depósito de blob. ~64 KB de
    -- texto cifrado por nota é folgado para um diário.
    constraint notes_content_cipher_tamanho   check (length(content_cipher) <= 131072)
);

comment on table  public.notes is
    'Anotações do diário. title_cipher/content_cipher são AES-256-GCM em Base64, cifrados no cliente.';
comment on column public.notes.user_id is
    'Dono da nota. Preenchido por default auth.uid() e travado pelas policies de RLS.';

-- -----------------------------------------------------------------------------
-- Índices
-- -----------------------------------------------------------------------------
-- Toda consulta do app é "as minhas notas, mais recentes primeiro". O índice
-- composto (user_id, created_at desc) atende a policy de RLS e o ORDER BY com
-- a mesma estrutura. Índice em user_id é obrigatório em tabelas com RLS: sem
-- ele, o predicado auth.uid() = user_id vira sequential scan.
create index if not exists notes_user_id_created_at_idx
    on public.notes (user_id, created_at desc);

-- -----------------------------------------------------------------------------
-- Trigger de updated_at
-- search_path = '' força a qualificação completa de nomes dentro da função,
-- fechando a porta para sequestro de search_path (recomendação do Supabase).
-- -----------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = ''
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

comment on function public.set_updated_at() is
    'Atualiza updated_at em qualquer UPDATE. security invoker + search_path vazio.';

drop trigger if exists notes_set_updated_at on public.notes;
create trigger notes_set_updated_at
    before update on public.notes
    for each row execute function public.set_updated_at();

drop trigger if exists diary_keys_set_updated_at on public.diary_keys;
create trigger diary_keys_set_updated_at
    before update on public.diary_keys
    for each row execute function public.set_updated_at();
