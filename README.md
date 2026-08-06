# 🔐 Diário Pessoal Criptografado

**Um diário em que nem o dono do banco de dados consegue ler o que você
escreveu.**

Aplicação completa de anotações pessoais construída sobre **Supabase
(PostgreSQL)**, com duas camadas independentes de proteção: **Row Level
Security** isolando cada usuário dentro do banco e **criptografia ponta a
ponta** (AES-256-GCM) tornando o conteúdo ilegível para o servidor.

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Supabase" src="https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?logo=supabase&logoColor=white">
  <img alt="Streamlit" src="https://img.shields.io/badge/Streamlit-app-FF4B4B?logo=streamlit&logoColor=white">
  <img alt="Testes" src="https://img.shields.io/badge/testes-67%20pytest%20%2B%2018%20pgTAP-success">
</p>

---

## O problema

Todo aplicativo multiusuário precisa responder a uma pergunta simples: *como
garantir que o usuário A jamais alcance os dados do usuário B?*

A resposta comum é filtrar no código da aplicação:

```python
notas = db.query("select * from notes where user_id = %s", usuario.id)
```

Funciona — até o dia em que alguém escreve um endpoint novo e esquece o
`where`. Ou o cliente passa a falar direto com o banco (é exatamente o que
acontece no Supabase: o navegador conversa com a API do PostgREST).

E, mesmo com o filtro correto, permanece a pergunta seguinte: *quem administra
o banco lê o quê?* Num diário pessoal, isso não é detalhe.

## A solução

**Duas barreiras independentes**, cada uma cobrindo o ponto cego da outra:

| Camada | Onde vive | O que garante |
|---|---|---|
| Row Level Security | dentro do PostgreSQL | nenhuma consulta alcança linha de outro usuário — venha ela do app, de um cliente REST ou do SQL Editor |
| Criptografia ponta a ponta | no cliente, antes da rede | mesmo com acesso total ao banco, título e conteúdo são bytes indecifráveis |

Se o RLS falhasse, o invasor levaria texto cifrado. Se a criptografia fosse
quebrada, o RLS não teria entregado as linhas.

---

## O desafio central: `auth.uid() = user_id`

Uma regra, aplicada às quatro operações — e as decisões por trás dela:

```sql
alter table public.notes enable row level security;
alter table public.notes force  row level security;   -- vale até para o dono da tabela

revoke all on public.notes from anon;                 -- visitante nem chega ao RLS
grant select, insert, update, delete on public.notes to authenticated;

create policy "notes_select_proprias" on public.notes
    for select to authenticated
    using ( (select auth.uid()) = user_id );          -- subquery: avaliada 1x, não por linha

create policy "notes_insert_proprias" on public.notes
    for insert to authenticated
    with check ( (select auth.uid()) = user_id );

create policy "notes_update_proprias" on public.notes
    for update to authenticated
    using      ( (select auth.uid()) = user_id )      -- não alcanço nota alheia
    with check ( (select auth.uid()) = user_id );     -- nem transfiro a minha para outro

create policy "notes_delete_proprias" on public.notes
    for delete to authenticated
    using ( (select auth.uid()) = user_id );
```

Do lado da aplicação, o resultado é um código de acesso a dados que **não
filtra por usuário em lugar nenhum**:

```python
# src/diario/backends/supabase_backend.py
def listar_notas(self) -> list[NotaCifrada]:
    # Repare: nenhum filtro por usuário. O RLS já devolve só o que é meu.
    dados = self._executar(
        lambda: self._client.table("notes").select("*").order("created_at", desc=True).execute()
    )
    return [NotaCifrada.de_dict(linha) for linha in dados]
```

É a diferença entre *filtrar por usuário* e *isolar por usuário*.

O projeto trata explicitamente as armadilhas clássicas de RLS — views que
ignoram policies, o dono da tabela passando por cima, a `service_role` key com
`BYPASSRLS`, índice ausente em `user_id`. Todas comentadas em
**[docs/RLS.md](docs/RLS.md)**.

---

## A criptografia

```
passphrase do diário ──Scrypt(salt, N=2¹⁵)──► KEK ──AES-GCM──► DEK ──AES-GCM──► notas
     (nunca sai do cliente)                              (no banco só a versão embrulhada)
```

* **Envelope encryption**: trocar a passphrase re-embrulha a chave de dados —
  nenhuma nota é reescrita, mesmo com milhares de registros.
* **AES-256-GCM (AEAD)**: um bit alterado invalida a decifragem.
* **O `user_id` entra como dado associado (AAD)**: um ciphertext copiado para
  a linha de outro usuário simplesmente não abre — a criptografia reforçando o
  isolamento que o banco já garante.
* **Scrypt memory-hard**: ~32 MB e ~100 ms por derivação; imperceptível para o
  usuário, proibitivo para força bruta.

O que o servidor guarda de uma anotação:

```json
{
  "title_cipher":   "QZSnoTXufji93027sDgrU0B0eCdcaYYcU5qe9kbsktyneRR+6dCze6WfT2pTuAl/vden0707h1fu",
  "content_cipher": "OPVkvM95v4vCH+z/9qXxKoY3xy8g2mW8LdWJsNVQzCydtbcRFfnaBwOUUs6OLGBu9LW1v1CYWLoJ…"
}
```

Detalhes, modelo de ameaças e **limitações conhecidas** em
**[docs/SEGURANCA_E_CRIPTOGRAFIA.md](docs/SEGURANCA_E_CRIPTOGRAFIA.md)**.

---

## Como a segurança é verificada

Segurança que não é testada é opinião. Aqui ela é verificada em três camadas
independentes:

```bash
pytest                            # 67 testes
supabase test db                  # 18 asserções pgTAP, dentro do PostgreSQL
python scripts/verificar_rls.py   # auditoria contra um projeto Supabase real
```

**1. pgTAP — dentro do banco.** Dois usuários reais são encarnados na
transação, alternando papel e claims do JWT exatamente como o PostgREST faz.
Cobre SELECT isolado, UPDATE/DELETE afetando zero linhas, INSERT forjado
recusado com `42501`, visitante anônimo barrado, view e função respeitando o
RLS.

**2. pytest — a regra e o app.** Inclui um guarda-corpo que lê as migrations e
falha se faltar uma policy, se o RLS não estiver habilitado, se aparecer um
`using (true)` ou se um `UPDATE` ficar sem `WITH CHECK`. Pega em segundos o
erro que passaria numa revisão de código.

**3. Auditoria no projeto real.** Cria duas contas, escreve com a primeira e
tenta invadir com a segunda pela mesma API que o app usa:

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

## Rodando em 30 segundos

O projeto roda **sem nenhuma conta na nuvem**: há um modo demonstração em
SQLite, sinalizado em tela, para quem quer só ver o produto funcionando.

```bash
python -m venv .venv && .venv\Scripts\activate    # Windows
pip install -r requirements-dev.txt

python scripts/gerar_massa_demo.py --recriar
streamlit run app.py
```

| Conta | Senha | Passphrase do diário |
|---|---|---|
| `alice@exemplo.test` | `senha-da-conta` | `cafe-com-leite-42` |
| `bruno@exemplo.test` | `senha-da-conta` | `montanha-azul-77` |

**Com Supabase de verdade:** copie `.env.example` para `.env`, preencha URL e
anon key, aplique as três migrations e rode. Passo a passo em
**[docs/GUIA_DE_USO.md](docs/GUIA_DE_USO.md)**.

---

## A interface

Três abas, cada uma servindo a um propósito:

* **📓 Minhas notas** — escrever, buscar, editar e excluir; com um painel
  "ver o que o servidor guarda desta nota" que mostra o Base64 real da linha.
* **🛡️ Prova de isolamento** — cole o `id` de uma nota de outro usuário e
  tente lê-la. Mostra lado a lado quantas linhas existem na tabela e quantas a
  sua sessão alcança.
* **🔑 Segurança** — troca de passphrase (instantânea, sem reescrever notas) e
  o mapa de como as chaves se encaixam.

---

## Stack

| Camada | Tecnologia | Por quê |
|---|---|---|
| Banco | PostgreSQL (Supabase) | Row Level Security nativo — isolamento no motor, não no app |
| Autenticação | Supabase Auth (GoTrue) | JWT que alimenta `auth.uid()` dentro das policies |
| API | PostgREST | o cliente fala direto com o banco; sem RLS, não haveria projeto |
| Criptografia | `cryptography` (AES-256-GCM + Scrypt) | AEAD e KDF memory-hard, sem dependência extra |
| Interface | Streamlit | UI em Python puro, foco no que o projeto quer demonstrar |
| Testes | pytest + `AppTest` + pgTAP | regra verificada no app **e** dentro do banco |

---

## Estrutura

```
├── app.py                       # interface Streamlit
├── src/diario/
│   ├── crypto.py                # Scrypt + AES-256-GCM, envelope de chaves
│   ├── service.py               # casos de uso (cifra na escrita, decifra na leitura)
│   ├── repository.py            # contrato de persistência
│   └── backends/                # Supabase (RLS real) e SQLite (demonstração)
├── supabase/
│   ├── migrations/              # schema, policies, hardening
│   ├── tests/rls_notes_test.sql # 18 asserções pgTAP
│   └── seed.sql
├── scripts/
│   ├── verificar_rls.py         # auditoria contra projeto real
│   └── gerar_massa_demo.py      # massa de demonstração cifrada
├── tests/                       # 67 testes
└── docs/
```

---

## Documentação

| Documento | Conteúdo |
|---|---|
| **[docs/RLS.md](docs/RLS.md)** | O desafio central: `USING` × `WITH CHECK`, armadilhas, diagnóstico e como o projeto cresceria |
| **[docs/SEGURANCA_E_CRIPTOGRAFIA.md](docs/SEGURANCA_E_CRIPTOGRAFIA.md)** | Modelo de ameaças, arquitetura de chaves e limitações conhecidas |
| **[docs/ARQUITETURA.md](docs/ARQUITETURA.md)** | Camadas, modelo de dados, fluxos e decisões de projeto |
| **[docs/GUIA_DE_USO.md](docs/GUIA_DE_USO.md)** | Instalação, Supabase, comandos e problemas comuns |
| **[docs/REFERENCIA_API.md](docs/REFERENCIA_API.md)** | Referência dos módulos do pacote `diario` |

---

## O que este projeto demonstra

* Modelagem de segurança **no banco de dados**, não no framework da vez
* Domínio de PostgreSQL além do CRUD: policies, `GRANT`/`REVOKE`, `security
  invoker`, `FORCE RLS`, impacto de RLS no plano de execução
* Criptografia aplicada com decisões justificadas (AEAD, KDF memory-hard,
  envelope encryption, AAD amarrando o dado ao dono)
* Arquitetura em camadas com contrato explícito e dois backends intercambiáveis
* Testes que verificam a **regra de segurança**, não só o caminho feliz
* Documentação que assume as limitações da própria implementação

---

## Autor

**Leandro Miozzo Bonato** — 14 anos em desenvolvimento e bancos de dados
(Oracle, PL/SQL, Firebird, SQL Server), com pós-graduação em Banco de Dados e
em Ciência de Dados, Machine Learning e Deep Learning (PUC-Rio).

[GitHub](https://github.com/leandrobonato) ·
[LinkedIn](https://linkedin.com/in/leandro-miozzo-bonato)
