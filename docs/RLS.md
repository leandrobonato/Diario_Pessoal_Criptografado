# Row Level Security na prática

> Documento de referência do desafio central deste projeto: **garantir que um
> usuário autenticado leia e escreva apenas as próprias notas**.

---

## 1. O problema, em uma frase

Num backend tradicional, o isolamento entre usuários mora no código:

```python
# em algum lugar da API
notas = db.query("select * from notes where user_id = %s", usuario_atual.id)
```

Funciona — até o dia em que alguém escreve um endpoint novo e esquece o
`where`. Ou expõe um filtro dinâmico. Ou o cliente passa a falar direto com o
banco (é exatamente o que o Supabase faz: o navegador conversa com o PostgREST).

O Row Level Security move essa responsabilidade para dentro do PostgreSQL.
A regra deixa de ser uma linha de código que pode ser esquecida e passa a ser
uma propriedade da tabela: **não existe consulta capaz de contornar**, venha
ela do app, do SQL Editor, de um cliente REST ou de um `psql`.

---

## 2. A regra deste projeto

```sql
auth.uid() = user_id
```

`auth.uid()` é uma função do Supabase que lê o `sub` do JWT do usuário
autenticado. Ela devolve `NULL` quando não há JWT — e `NULL = qualquer coisa`
é `NULL`, que não é `TRUE`. Ou seja: **sem login, nenhuma linha passa**, sem
precisar de nenhuma cláusula extra.

Aplicada às quatro operações:

| Operação | Cláusula | Impede |
|---|---|---|
| `SELECT` | `USING` | ler nota alheia |
| `INSERT` | `WITH CHECK` | gravar nota em nome de outro |
| `UPDATE` | `USING` + `WITH CHECK` | editar nota alheia **e** transferir a própria nota para outro dono |
| `DELETE` | `USING` | apagar nota alheia |

### USING × WITH CHECK

É a distinção que mais gera bug em projeto Supabase:

```
USING       → filtra as linhas que a operação PODE ENXERGAR   (SELECT, UPDATE, DELETE)
WITH CHECK  → valida as linhas que a operação PODE GRAVAR      (INSERT, UPDATE)
```

`UPDATE` precisa das duas. Com só `USING`, este ataque funciona:

```sql
-- Bruno alcança a própria nota (USING passa) e a transfere para a Alice
update notes set user_id = '<id-da-alice>' where id = '<nota-do-bruno>';
```

Com só `WITH CHECK`, o oposto: dá para editar linha alheia desde que o
resultado continue sendo de outra pessoa. As duas juntas fecham o cerco.

---

## 3. As policies, comentadas

Arquivo: [`supabase/migrations/20260731120100_rls_policies.sql`](../supabase/migrations/20260731120100_rls_policies.sql)

```sql
alter table public.notes enable row level security;

revoke all on public.notes from anon;
grant select, insert, update, delete on public.notes to authenticated;

create policy "notes_select_proprias"
    on public.notes for select to authenticated
    using ( (select auth.uid()) = user_id );

create policy "notes_insert_proprias"
    on public.notes for insert to authenticated
    with check ( (select auth.uid()) = user_id );

create policy "notes_update_proprias"
    on public.notes for update to authenticated
    using      ( (select auth.uid()) = user_id )
    with check ( (select auth.uid()) = user_id );

create policy "notes_delete_proprias"
    on public.notes for delete to authenticated
    using ( (select auth.uid()) = user_id );
```

Quatro decisões que valem explicação:

**1. `enable row level security` é obrigatório.** Sem ele, as policies existem
no catálogo e são simplesmente ignoradas. É o erro nº 1 em projetos Supabase —
o painel inclusive avisa em vermelho quando uma tabela pública está sem RLS.

**2. `to authenticated` restringe o papel.** O PostgREST executa cada
requisição sob um papel: `anon` (sem token) ou `authenticated` (com JWT
válido). Amarrar a policy ao papel deixa explícito para quem ela vale.

**3. `revoke all ... from anon` é a camada de baixo.** GRANT e RLS são
independentes: o GRANT decide se a operação é permitida na tabela, o RLS
decide quais linhas ela alcança. Revogando o privilégio do visitante anônimo,
a requisição morre antes de chegar ao RLS — defesa em profundidade barata.

**4. `(select auth.uid())` em vez de `auth.uid()`.** Envolvida em subquery, a
função é avaliada uma única vez (InitPlan) e reaproveitada para todas as
linhas; solta, ela é reavaliada linha a linha. É a recomendação oficial de
performance de RLS do Supabase, e a diferença aparece já na casa dos milhares
de registros.

### O `DEFAULT auth.uid()` na coluna

```sql
user_id uuid not null references auth.users (id) on delete cascade default auth.uid()
```

Com esse default, o cliente não precisa informar o dono — e o repositório
Python de fato não informa:

```python
payload = {"title_cipher": ..., "content_cipher": ...}   # sem user_id
self._client.table("notes").insert(payload).execute()
```

Se um cliente malicioso mandar `user_id` de outra pessoa, o `WITH CHECK`
recusa com SQLSTATE `42501`. Default + policy = nem por descuido, nem por
malícia.

---

## 4. Armadilhas que este projeto trata explicitamente

### 4.1 Views ignoram o RLS por padrão

Uma view no PostgreSQL executa com os privilégios de **quem a criou**. Uma
view criada pelo `postgres` sobre uma tabela com RLS devolve as linhas de
todos os usuários — com o RLS ligado, aparentemente funcionando.

```sql
create or replace view public.minhas_notas_por_mes
with (security_invoker = on)   -- ← sem isto, vazamento silencioso
as select date_trunc('month', created_at)::date as mes, count(*) ...
```

`security_invoker = on` (PostgreSQL 15+) faz a view rodar com os privilégios
de quem consulta. Vale o mesmo para funções: as deste projeto são
`security invoker` por decisão explícita, não por acaso.

### 4.2 O dono da tabela passa por cima

`enable row level security` não vale para o dono da tabela. Um script
administrativo rodando como `postgres` continua enxergando tudo:

```sql
alter table public.notes force row level security;
```

Com `force`, nem o dono escapa. O `service_role` (que tem `BYPASSRLS`)
continua funcionando para backup e manutenção — esse é o caminho legítimo.

### 4.3 A service_role key ignora tudo

A `service_role` foi criada com `BYPASSRLS`: ela **ignora todas as policies**.
Ela existe para jobs de servidor. Se vazar para o cliente, todo o isolamento
deste projeto vira decoração.

Por isso o app:

* usa exclusivamente a **anon key** (pública por definição e inútil sozinha);
* varre o ambiente atrás de variáveis com `SERVICE_ROLE`/`SERVICE_KEY` no nome
  e exibe alerta vermelho em tela se achar
  ([`src/diario/config.py`](../src/diario/config.py)).

### 4.4 Tabela com RLS sem índice em `user_id`

O predicado da policy entra em toda consulta. Sem índice, vira sequential
scan a cada `SELECT`. Aqui:

```sql
create index notes_user_id_created_at_idx on public.notes (user_id, created_at desc);
```

O índice composto atende a policy e o `order by created_at desc` da listagem
com a mesma estrutura.

### 4.5 "Não existe" e "não é seu" são indistinguíveis

O RLS filtra antes do `WHERE`: um `UPDATE` numa nota alheia afeta **zero
linhas**, exatamente como numa nota inexistente. O app preserva esse
comportamento — a mensagem de erro é a mesma nos dois casos, para que ela não
vire um oráculo de existência de registros.

---

## 5. Como isto é verificado

Três camadas independentes, porque cada uma pega o que a outra não vê:

### 5.1 pgTAP — dentro do PostgreSQL

[`supabase/tests/rls_notes_test.sql`](../supabase/tests/rls_notes_test.sql) —
18 asserções que encarnam dois usuários reais alternando o papel e as claims
do JWT, exatamente como o PostgREST faz:

```sql
set local request.jwt.claims = '{"sub": "<uuid>", "role": "authenticated"}';
set local role authenticated;
```

```bash
supabase test db
```

Cobre: RLS habilitado e forçado, as 8 policies esperadas, `DEFAULT auth.uid()`,
SELECT isolado, UPDATE/DELETE afetando zero linhas, INSERT forjado recusado
com `42501`, `anon` barrado pelo GRANT, view e função respeitando o RLS.

### 5.2 pytest — a regra e o app

```bash
pytest
```

* [`tests/test_migrations_sql.py`](../tests/test_migrations_sql.py) — lê as
  migrations e falha se faltar uma policy, se o RLS não estiver habilitado, se
  aparecer um `using (true)`, se um `UPDATE` ficar sem `WITH CHECK`, se sumir o
  índice ou o `security_invoker`. Pega em segundos o erro que passaria numa
  revisão de código.
* [`tests/test_isolamento_usuarios.py`](../tests/test_isolamento_usuarios.py) —
  os mesmos cenários do pgTAP, rodando no modo demonstração.

### 5.3 Auditoria contra o projeto real

```bash
python scripts/verificar_rls.py
```

Cria (ou reaproveita) duas contas reais, escreve uma nota com a primeira e
tenta invadir com a segunda pela mesma API que o app usa. Sai com código 1 se
qualquer tentativa passar.

Saída esperada:

```
[ok] PASSOU  SELECT: B não enxerga a nota de A na listagem
[ok] PASSOU  SELECT por id: a nota de A não retorna para B
[ok] PASSOU  UPDATE: B não altera a nota de A
[ok] PASSOU  DELETE: B não apaga a nota de A
[ok] PASSOU  INSERT: B não grava nota em nome de A (WITH CHECK)
[ok] PASSOU  diary_keys: B só alcança o próprio cofre
[ok] PASSOU  anon: visitante sem login é barrado
[ok] PASSOU  A nota de A continua intacta após as tentativas de B
```

---

## 6. Consultas úteis de diagnóstico

```sql
-- Tabelas públicas sem RLS habilitado (deveria voltar vazio)
select schemaname, tablename
from pg_tables
where schemaname = 'public'
  and tablename not in (
      select tablename from pg_tables t
      join pg_class c on c.relname = t.tablename
      where c.relrowsecurity
  );

-- Todas as policies do schema public
select tablename, policyname, cmd, qual as using_expr, with_check
from pg_policies
where schemaname = 'public'
order by tablename, cmd;

-- RLS habilitado e forçado, por tabela
select relname, relrowsecurity as habilitado, relforcerowsecurity as forcado
from pg_class
where relname in ('notes', 'diary_keys');

-- O RLS está sendo usado no plano? Procure por "Filter" no resultado
explain analyze select * from public.notes order by created_at desc limit 20;
```

---

## 7. Se este projeto crescesse

| Necessidade | Caminho |
|---|---|
| Notas compartilhadas com outra pessoa | Tabela `note_shares (note_id, shared_with)` + policy adicional de `SELECT` com `exists (...)`; policies são **permissivas** por padrão, então basta somar uma nova |
| Diários de equipe | Coluna `team_id` + tabela de membros; a policy compara `auth.uid()` contra a associação, não contra o dono |
| Papel de administrador | Claim customizada no JWT (`app_metadata.role`) lida na policy — nunca uma tabela consultada sem cuidado, sob risco de recursão de policy |
| Soft delete | Coluna `deleted_at` + policy de `SELECT` com `deleted_at is null`, mantendo o `DELETE` real para o dono |
| Auditoria de acesso | Tabela append-only com policy de `INSERT` para `authenticated` e **nenhuma** policy de `SELECT`/`UPDATE`/`DELETE` — só o `service_role` lê |
