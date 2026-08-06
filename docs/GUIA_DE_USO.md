# Guia de uso

Do zero ao diário rodando — primeiro no modo demonstração (sem cadastro
nenhum), depois com um projeto Supabase real.

---

## 1. Pré-requisitos

* Python 3.11 ou superior
* Para o RLS de verdade: uma conta gratuita no [Supabase](https://supabase.com)
* Para rodar os testes pgTAP: [Supabase CLI](https://supabase.com/docs/guides/local-development)
  e Docker (opcional)

---

## 2. Instalação

```bash
git clone <url-do-repositorio>
cd Diario_Pessoal_Criptografado

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # Linux/macOS

pip install -r requirements-dev.txt
```

---

## 3. Modo demonstração (30 segundos, sem nuvem)

```bash
python scripts/gerar_massa_demo.py --recriar
streamlit run app.py
```

O app abre em `http://localhost:8501`. Contas criadas pelo script:

| Conta | Senha da conta | Passphrase do diário |
|---|---|---|
| `alice@exemplo.test` | `senha-da-conta` | `cafe-com-leite-42` |
| `bruno@exemplo.test` | `senha-da-conta` | `montanha-azul-77` |

> ⚠️ Nesse modo os dados ficam num SQLite em `data/diario_demo.db` e o
> isolamento é **reproduzido na aplicação**, não pelo PostgreSQL. Serve para
> ver o produto funcionando; para exercitar o RLS de verdade, siga a seção 4.
> O app deixa isso explícito com um aviso na barra lateral.

### Roteiro sugerido de demonstração

1. Entre como `alice`, abra uma nota e expanda **"Ver o que o servidor guarda
   desta nota"** — é o Base64 que existe na camada de dados.
2. Copie o `id` dessa nota (aba **🛡️ Prova de isolamento**).
3. Saia, entre como `bruno`, cole o id na aba de isolamento e clique em
   **Tentar ler esta nota**: nada retorna.
4. Compare as duas métricas no rodapé da aba: linhas na tabela × linhas que a
   sessão enxerga.

---

## 4. Com um projeto Supabase real

### 4.1 Criar o projeto

1. Crie um projeto em [supabase.com/dashboard](https://supabase.com/dashboard).
2. Em **Authentication → Providers → Email**, **desligue "Confirm email"** (em
   projeto de teste isso evita ter de confirmar cada cadastro por e-mail).
3. Em **Project Settings → API**, copie a **Project URL** e a **anon public key**.

> Nunca copie a `service_role key` para o app: ela tem `BYPASSRLS` e ignora
> todas as policies deste projeto.

### 4.2 Configurar o `.env`

```bash
copy .env.example .env      # Windows
cp .env.example .env        # Linux/macOS
```

```bash
SUPABASE_URL=https://xxxxxxxxxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOi...
DIARIO_BACKEND=auto
```

Com `auto`, o app usa o Supabase quando há URL + chave e cai no modo
demonstração quando não há.

### 4.3 Aplicar as migrations

**Opção A — SQL Editor (mais rápido):** abra o SQL Editor do painel e execute,
**nesta ordem**, o conteúdo de:

1. `supabase/migrations/20260731120000_init_schema.sql`
2. `supabase/migrations/20260731120100_rls_policies.sql`
3. `supabase/migrations/20260731120200_hardening_e_visoes.sql`

**Opção B — Supabase CLI:**

```bash
supabase init          # só se ainda não houver supabase/config.toml
supabase link --project-ref <ref-do-projeto>
supabase db push
```

### 4.4 Rodar

```bash
streamlit run app.py
```

Crie uma conta pelo próprio app, defina a passphrase do diário e escreva.

### 4.5 Auditar o isolamento

```bash
python scripts/verificar_rls.py
```

Duas contas reais, uma tentando invadir a outra pela mesma API que o app usa.
Sai com código 1 se qualquer tentativa passar.

---

## 5. Ambiente local completo (Supabase CLI + Docker)

```bash
supabase init          # cria supabase/config.toml, se ainda não existir
supabase start         # sobe Postgres, Auth, PostgREST e Studio em containers
supabase db reset      # aplica as migrations e roda o seed.sql
supabase test db       # executa os testes pgTAP de RLS
```

O `supabase start` imprime a URL da API e a anon key locais — é só colocá-las
no `.env` para o app apontar para o ambiente local.

Saída esperada de `supabase test db`:

```
rls_notes_test.sql .. ok
All tests successful.
```

---

## 6. Testes

```bash
pytest                                  # 67 testes
pytest -v                               # detalhado
pytest tests/test_crypto.py -v          # só a criptografia
pytest -k isolamento -v                 # só o isolamento entre usuários
pytest tests/test_migrations_sql.py -v  # só o guarda-corpo das policies
```

---

## 7. Variáveis de ambiente

| Variável | Padrão | Para que serve |
|---|---|---|
| `SUPABASE_URL` | — | URL do projeto |
| `SUPABASE_ANON_KEY` | — | chave pública (**nunca** a service_role) |
| `DIARIO_BACKEND` | `auto` | `auto`, `supabase` ou `local` |
| `DIARIO_DB_PATH` | `data/diario_demo.db` | banco do modo demonstração |

---

## 8. Problemas comuns

| Sintoma | Causa provável | Solução |
|---|---|---|
| "Conta criada, mas é preciso confirmar o e-mail" | "Confirm email" ligado no projeto | Authentication → Providers → Email → desligar |
| O app abre em modo demonstração sem eu pedir | `.env` ausente ou sem URL/chave | Preencher `SUPABASE_URL` e `SUPABASE_ANON_KEY` |
| `relation "public.notes" does not exist` | migrations não aplicadas | Seção 4.3 |
| `new row violates row-level security policy` ao gravar | JWT ausente/expirado, ou `user_id` sendo enviado à mão | Refazer login; não envie `user_id` — o `DEFAULT auth.uid()` cuida disso |
| `permission denied for table notes` | requisição sem autenticação (papel `anon`) | Fazer login antes; é o comportamento esperado para visitante |
| SELECT devolve vazio mesmo com dados no banco | as linhas são de outro usuário | Comportamento correto do RLS |
| Alerta vermelho "Chave de serviço detectada" | há `SERVICE_ROLE`/`SERVICE_KEY` no ambiente | Remover do `.env`/ambiente: ela ignora o RLS |
| "Passphrase do diário incorreta" | passphrase errada (ou cofre de outro usuário) | Não há recuperação — ver `docs/SEGURANCA_E_CRIPTOGRAFIA.md` |
| `supabase test db` não encontra pgTAP | extensão não habilitada no ambiente local | `create extension if not exists pgtap with schema extensions;` |
| `ModuleNotFoundError: diario` | venv não ativado ou dependências ausentes | Ativar o venv e reinstalar os requirements |

---

## 9. Como apagar tudo e recomeçar

```bash
# modo demonstração
rm -rf data/                       # Linux/macOS
Remove-Item -Recurse -Force data   # Windows PowerShell
python scripts/gerar_massa_demo.py --recriar

# Supabase local
supabase db reset
```
