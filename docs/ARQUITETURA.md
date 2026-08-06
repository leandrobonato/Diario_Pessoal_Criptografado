# Arquitetura

---

## 1. Visão geral

```
┌──────────────────────────────────────────────────────────────────┐
│  app.py — Streamlit                                              │
│  apresentação, estado de sessão, tradução de exceção em mensagem │
└───────────────────────────────┬──────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│  diario.service — casos de uso                                   │
│  única camada que vê texto em claro E fala com o repositório     │
│  toda escrita passa por cifrar_texto, toda leitura por decifrar  │
└──────────┬────────────────────────────────────┬──────────────────┘
           │                                    │
┌──────────▼─────────────┐        ┌─────────────▼───────────────────┐
│ diario.crypto          │        │ diario.repository (Protocol)    │
│ Scrypt + AES-256-GCM   │        │ contrato de persistência        │
└────────────────────────┘        └─────┬───────────────────┬───────┘
                                        │                   │
                         ┌──────────────▼──────┐  ┌─────────▼─────────────┐
                         │ supabase_backend    │  │ local_backend         │
                         │ Auth + PostgREST    │  │ SQLite (demonstração) │
                         └──────────┬──────────┘  └───────────────────────┘
                                    │
                    ┌───────────────▼────────────────┐
                    │ PostgreSQL + Row Level Security│
                    │ auth.uid() = user_id           │
                    └────────────────────────────────┘
```

Duas regras estruturam tudo:

1. **A UI nunca toca no repositório direto.** Ela chama o serviço; o serviço
   decide o que cifrar.
2. **O repositório Supabase nunca filtra por usuário.** Não existe
   `where user_id = ...` em lugar nenhum do código de acesso a dados — quem
   isola é o banco. É intencional: se o filtro estivesse no app, um endpoint
   novo mal escrito reabriria o vazamento.

---

## 2. Estrutura de pastas

```
Diario_Pessoal_Criptografado/
├── app.py                          # interface Streamlit (única camada de UI)
├── pyproject.toml                  # pacote, dependências e configuração do pytest
├── requirements.txt                # execução
├── requirements-dev.txt            # execução + testes
├── .env.example                    # modelo de configuração (o .env é ignorado)
│
├── src/diario/
│   ├── __init__.py                 # fachada do pacote
│   ├── config.py                   # leitura do .env, escolha de backend, alerta de service_role
│   ├── crypto.py                   # Scrypt + AES-256-GCM, envelope de chaves
│   ├── errors.py                   # exceções de domínio
│   ├── models.py                   # Nota (em claro) × NotaCifrada (no banco)
│   ├── repository.py               # Protocol + fábrica de backend
│   ├── service.py                  # casos de uso
│   └── backends/
│       ├── supabase_backend.py     # Supabase Auth + PostgREST
│       └── local_backend.py        # SQLite com a política reproduzida em Python
│
├── supabase/
│   ├── migrations/
│   │   ├── 20260731120000_init_schema.sql        # tabelas, índices, triggers
│   │   ├── 20260731120100_rls_policies.sql       # as 8 policies + grants
│   │   └── 20260731120200_hardening_e_visoes.sql # FORCE RLS, view e função security invoker
│   ├── tests/rls_notes_test.sql                  # 18 asserções pgTAP
│   └── seed.sql                                  # massa local (supabase db reset)
│
├── scripts/
│   ├── verificar_rls.py            # auditoria contra um projeto Supabase real
│   └── gerar_massa_demo.py         # popula o modo demonstração com dados cifrados
│
├── tests/                          # 67 testes pytest
│   ├── conftest.py
│   ├── test_crypto.py              # garantias criptográficas
│   ├── test_isolamento_usuarios.py # isolamento entre usuários
│   ├── test_service.py             # fluxos do diário
│   ├── test_migrations_sql.py      # guarda-corpo das policies
│   └── test_app_streamlit.py       # ponta a ponta da UI, via AppTest
│
├── data/                           # artefatos gerados (ignorados pelo Git)
└── docs/
    ├── ARQUITETURA.md              # este documento
    ├── RLS.md                      # o desafio central, em profundidade
    ├── SEGURANCA_E_CRIPTOGRAFIA.md # modelo de ameaças e desenho das chaves
    ├── GUIA_DE_USO.md              # instalação, Supabase, comandos, problemas comuns
    └── REFERENCIA_API.md           # referência dos módulos
```

---

## 3. Modelo de dados

### `public.notes`

| Coluna | Tipo | Observação |
|---|---|---|
| `id` | `uuid` PK | `default gen_random_uuid()` |
| `user_id` | `uuid` NOT NULL | FK → `auth.users(id)` `on delete cascade`, `default auth.uid()` |
| `title_cipher` | `text` | Base64 de `nonce ‖ ciphertext ‖ tag` |
| `content_cipher` | `text` | idem; `check length <= 131072` |
| `crypto_version` | `smallint` | versionamento do formato criptográfico |
| `created_at` / `updated_at` | `timestamptz` | `updated_at` por trigger |

Índice: `(user_id, created_at desc)` — atende o predicado da policy e a
ordenação da listagem.

### `public.diary_keys`

| Coluna | Tipo | Observação |
|---|---|---|
| `user_id` | `uuid` PK | FK → `auth.users(id)`, `default auth.uid()` |
| `kdf_salt` | `text` | salt do Scrypt em Base64 (público por definição) |
| `kdf_params` | `jsonb` | `{"algorithm":"scrypt","n":32768,"r":8,"p":1,"length":32}` |
| `wrapped_dek` | `text` | DEK cifrada com a KEK |
| `crypto_version` | `smallint` | |

Um registro por usuário. Gravar os parâmetros do KDF junto do salt permite
endurecer o custo no futuro sem invalidar cofres existentes.

### `public.minhas_notas_por_mes`

View agregada com `security_invoker = on` — respeita o RLS da tabela de
origem. Ver [RLS.md, seção 4.1](RLS.md).

---

## 4. Fluxos

### 4.1 Primeiro acesso

```
usuário → criar conta            → Supabase Auth cria o usuário e devolve o JWT
       → definir passphrase      → Scrypt(salt aleatório) → KEK
                                 → DEK aleatória de 32 bytes
                                 → AES-GCM(DEK, KEK) → wrapped_dek
       → INSERT em diary_keys    → policy WITH CHECK confere auth.uid() = user_id
```

### 4.2 Escrever uma nota

```
texto em claro
   → service.criar_nota
   → crypto.cifrar_texto(titulo, DEK, aad="note:<user_id>")
   → crypto.cifrar_texto(conteudo, DEK, aad="note:<user_id>")
   → repositorio.criar_nota({title_cipher, content_cipher})   ← sem user_id
   → PostgREST → INSERT
       • DEFAULT auth.uid() preenche user_id
       • WITH CHECK valida o dono
```

### 4.3 Abrir o diário numa nova sessão

```
login → JWT
      → SELECT em diary_keys (RLS devolve só a linha do usuário)
      → passphrase + kdf_salt + kdf_params → KEK
      → AES-GCM abre wrapped_dek → DEK
      → SELECT em notes (RLS devolve só as notas do usuário)
      → decifra em memória
```

### 4.4 Trocar a passphrase

```
passphrase atual → abre o cofre → DEK em memória
nova passphrase  → novo salt → nova KEK → novo wrapped_dek
UPDATE em diary_keys (uma linha)
```

Nenhuma nota é lida, decifrada ou reescrita — é o ponto do envelope
encryption.

---

## 5. Decisões de projeto

**Dois backends atrás do mesmo contrato.** O Supabase é o alvo real; o SQLite
existe para que qualquer pessoa clone e rode em 30 segundos, sem conta na
nuvem e sem Docker. Trocar entre eles é uma variável de ambiente
(`DIARIO_BACKEND`), e nenhuma linha da UI muda. O modo demonstração é
sinalizado em tela para não induzir ninguém a achar que está exercitando o RLS
de verdade.

**A política do backend local mora numa classe única.** `PoliticaDeLinha`
concentra o predicado `user_id = :uid` e a validação de gravação; não existe
consulta no backend local que escape dela — assim como não existe consulta no
Postgres que escape do RLS. É uma reprodução didática, e o código diz isso com
todas as letras.

**Zero `where user_id` no backend Supabase.** Ver seção 1. É o que separa
"filtrar por usuário" de "isolar por usuário".

**Tipos separados para nota cifrada e nota em claro.** `NotaCifrada` e `Nota`
são classes diferentes. Evita o acidente mais caro possível aqui: mandar texto
em claro para o banco por engano.

**A busca é local, e isso está documentado.** Consequência inevitável da
criptografia ponta a ponta, não descuido de implementação. Ver
[SEGURANCA_E_CRIPTOGRAFIA.md, seção 5](SEGURANCA_E_CRIPTOGRAFIA.md).

**Erros de domínio, não exceções de biblioteca.** O `PostgREST` devolve
SQLSTATE `42501` quando o `WITH CHECK` recusa; o backend traduz para
`AcessoNegado`, e a UI decide a mensagem. A camada de cima nunca precisa saber
que existe HTTP no meio do caminho.

**Widgets com `key` explícita.** Todo campo e botão do Streamlit tem `key`.
Isso permite que `tests/test_app_streamlit.py` selecione elementos por
identidade em vez de posição — o teste continua valendo quando a tela muda de
layout.

---

## 6. Testes

| Camada | Arquivo | Roda onde |
|---|---|---|
| Criptografia | `tests/test_crypto.py` | pytest |
| Isolamento entre usuários | `tests/test_isolamento_usuarios.py` | pytest (backend local) |
| Fluxos do diário | `tests/test_service.py` | pytest |
| Policies (guarda-corpo) | `tests/test_migrations_sql.py` | pytest, lendo o SQL |
| Interface ponta a ponta | `tests/test_app_streamlit.py` | pytest via `AppTest` |
| RLS de verdade | `supabase/tests/rls_notes_test.sql` | `supabase test db` (pgTAP) |
| Projeto real | `scripts/verificar_rls.py` | contra um Supabase de verdade |

```bash
pytest                    # 67 testes
supabase test db          # 18 asserções pgTAP (exige Supabase CLI + Docker)
python scripts/verificar_rls.py
```

---

## 7. Ideias de evolução

* Migrar a cifragem para o navegador (Web Crypto API) — o schema não muda,
  só o local de execução do módulo `crypto`.
* Código de recuperação impresso no cadastro (segunda cópia da DEK embrulhada
  por uma chave aleatória mostrada uma única vez).
* Anexos cifrados via Supabase Storage, com policies equivalentes por bucket.
* Compartilhamento seletivo de notas (tabela `note_shares` + policy adicional).
* Exportação do diário em arquivo cifrado, com importação.
* Realtime: sincronizar notas entre dispositivos — o RLS vale igual nas
  subscrições.
