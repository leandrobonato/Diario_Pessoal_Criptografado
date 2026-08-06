-- =============================================================================
-- seed.sql — massa de demonstração para o ambiente LOCAL (supabase db reset)
--
-- ATENÇÃO: este arquivo cria usuários com senha conhecida direto no auth.users.
-- Serve exclusivamente para desenvolvimento local. NUNCA rode isto em produção.
--
-- Os textos cifrados abaixo são placeholders (Base64 arbitrário). Eles existem
-- para exercitar o RLS; não são envelopes AES-GCM válidos e, portanto, não
-- abrem no app. Para gerar massa que abre de verdade no app, use:
--     python scripts/gerar_massa_demo.py
-- =============================================================================

begin;

-- Alice e Bruno, senha "diario123" para ambos.
insert into auth.users (
    id, instance_id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at
)
values
    (
        '11111111-1111-1111-1111-111111111111',
        '00000000-0000-0000-0000-000000000000',
        'authenticated', 'authenticated',
        'alice@exemplo.test',
        extensions.crypt('diario123', extensions.gen_salt('bf')),
        now(), '{"provider": "email", "providers": ["email"]}', '{}',
        now(), now()
    ),
    (
        '22222222-2222-2222-2222-222222222222',
        '00000000-0000-0000-0000-000000000000',
        'authenticated', 'authenticated',
        'bruno@exemplo.test',
        extensions.crypt('diario123', extensions.gen_salt('bf')),
        now(), '{"provider": "email", "providers": ["email"]}', '{}',
        now(), now()
    )
on conflict (id) do nothing;

-- O GoTrue exige uma identidade vinculada para permitir login por e-mail/senha.
insert into auth.identities (
    id, user_id, provider_id, provider, identity_data, created_at, updated_at, last_sign_in_at
)
values
    (
        gen_random_uuid(), '11111111-1111-1111-1111-111111111111',
        'alice@exemplo.test', 'email',
        '{"sub": "11111111-1111-1111-1111-111111111111", "email": "alice@exemplo.test", "email_verified": true}',
        now(), now(), now()
    ),
    (
        gen_random_uuid(), '22222222-2222-2222-2222-222222222222',
        'bruno@exemplo.test', 'email',
        '{"sub": "22222222-2222-2222-2222-222222222222", "email": "bruno@exemplo.test", "email_verified": true}',
        now(), now(), now()
    )
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- As inserções abaixo passam pelo RLS de propósito: assumimos a identidade de
-- cada usuário, exatamente como o PostgREST faz. Se alguma policy estiver
-- errada, o seed FALHA — o que é uma forma barata de detectar regressão.
-- ---------------------------------------------------------------------------
set local request.jwt.claims = '{"sub": "11111111-1111-1111-1111-111111111111", "role": "authenticated"}';
set local role authenticated;

insert into public.diary_keys (kdf_salt, wrapped_dek)
values ('c2VlZC1zYWx0LWFsaWNlLTAwMDAwMDAw', 'c2VlZC13cmFwcGVkLWRlay1hbGljZS1wbGFjZWhvbGRlci0wMDAwMDA=')
on conflict (user_id) do nothing;

insert into public.notes (title_cipher, content_cipher)
values
    ('c2VlZC10aXR1bG8tYWxpY2UtMDEtcGxhY2Vob2xkZXItMDAwMDAwMDA=',
     'c2VlZC1jb250ZXVkby1hbGljZS0wMS1wbGFjZWhvbGRlci0wMDAwMDAwMA=='),
    ('c2VlZC10aXR1bG8tYWxpY2UtMDItcGxhY2Vob2xkZXItMDAwMDAwMDA=',
     'c2VlZC1jb250ZXVkby1hbGljZS0wMi1wbGFjZWhvbGRlci0wMDAwMDAwMA==');

reset role;
set local request.jwt.claims = '{"sub": "22222222-2222-2222-2222-222222222222", "role": "authenticated"}';
set local role authenticated;

insert into public.diary_keys (kdf_salt, wrapped_dek)
values ('c2VlZC1zYWx0LWJydW5vLTAwMDAwMDAw', 'c2VlZC13cmFwcGVkLWRlay1icnVuby1wbGFjZWhvbGRlci0wMDAwMDA=')
on conflict (user_id) do nothing;

insert into public.notes (title_cipher, content_cipher)
values
    ('c2VlZC10aXR1bG8tYnJ1bm8tMDEtcGxhY2Vob2xkZXItMDAwMDAwMDA=',
     'c2VlZC1jb250ZXVkby1icnVuby0wMS1wbGFjZWhvbGRlci0wMDAwMDAwMA==');

reset role;

commit;
