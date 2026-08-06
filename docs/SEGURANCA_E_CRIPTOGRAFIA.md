# Segurança e criptografia

> Como as notas são cifradas, o que exatamente o projeto protege — e, com a
> mesma honestidade, o que ele **não** protege.

---

## 1. Modelo de ameaças

| Ameaça | Protegido? | Por quê |
|---|---|---|
| Outro usuário autenticado tenta ler/alterar minhas notas | ✅ | Policies de RLS em `notes` e `diary_keys` |
| Visitante sem login consulta a API | ✅ | `revoke all ... from anon` + policies restritas a `authenticated` |
| Cliente malicioso forja `user_id` no INSERT | ✅ | `WITH CHECK` + `DEFAULT auth.uid()` |
| Vazamento do dump do banco | ✅ | Título e conteúdo são AES-256-GCM; sem a passphrase, são bytes |
| Administrador do banco lê as notas | ✅ | Mesma razão: a chave nunca chega ao servidor |
| Alguém copia o ciphertext de um usuário para a linha de outro | ✅ | O `user_id` entra como AAD do AES-GCM: o envelope não abre fora do dono |
| Adulteração do conteúdo cifrado | ✅ | GCM é autenticado: um bit alterado invalida a tag |
| Ataque de força bruta na passphrase | ⚠️ parcial | Scrypt (memory-hard) encarece muito, mas passphrase fraca continua sendo passphrase fraca |
| Usuário esquece a passphrase | ❌ por projeto | Não há recuperação — é a contrapartida do "nem o servidor abre" |
| Malware/keylogger na máquina do usuário | ❌ | Fora do alcance de qualquer criptografia em repouso |
| Metadados (quantas notas, quando foram escritas) | ❌ | `created_at`, `updated_at` e a contagem de linhas ficam em claro |
| Servidor Streamlit comprometido enquanto o cofre está aberto | ❌ | Ver a seção 6 — limitação conhecida desta implementação |

---

## 2. Arquitetura de chaves (envelope encryption)

```
passphrase do diário  (só na cabeça do usuário)
        │
        │  Scrypt(salt aleatório, N=2¹⁵, r=8, p=1)      ~100 ms, ~32 MB de RAM
        ▼
    KEK — Key Encryption Key (32 bytes)
        │
        │  AES-256-GCM   aad = "diary_key:<user_id>"
        ▼
 wrapped_dek ──────────────────────────────────►  public.diary_keys.wrapped_dek
        │
        │  (desembrulhada em memória, no cliente)
        ▼
    DEK — Data Encryption Key (32 bytes aleatórios)
        │
        │  AES-256-GCM   aad = "note:<user_id>"
        ▼
 title_cipher / content_cipher ─────────────────►  public.notes
```

### Por que duas chaves?

* **Trocar a passphrase não reescreve nenhuma nota.** Deriva-se a nova KEK e
  re-embrulha-se a *mesma* DEK: um `UPDATE` numa linha. Com uma chave só, a
  troca de senha exigiria decifrar e recifrar o diário inteiro.
* **A chave que protege os dados tem entropia máxima.** A DEK são 32 bytes de
  `secrets.token_bytes`, não uma senha humana.

### Por que Scrypt

É um KDF *memory-hard*: além de tempo de CPU, exige memória, o que encarece
ataque paralelo em GPU/ASIC. Com `N=2¹⁵, r=8, p=1` custa ~32 MB e ~100 ms por
tentativa — irrelevante para o usuário, proibitivo para quem quer testar
bilhões de senhas. E vem na própria `cryptography`, sem dependência extra.

Os parâmetros são gravados em `diary_keys.kdf_params` junto do salt. Isso
permite endurecer o custo para novos cofres no futuro sem invalidar os
antigos: cada usuário carrega os parâmetros com que o seu cofre foi criado.

### Por que AES-256-GCM

GCM é um modo **AEAD**: cifra e autentica na mesma operação. Qualquer
alteração no texto cifrado *ou nos dados associados* faz a decifragem falhar
com `InvalidTag` em vez de devolver lixo silenciosamente.

Os dados associados (AAD) carregam o `user_id`:

```python
def aad_nota(user_id: str) -> bytes:
    return f"note:{user_id}".encode("utf-8")
```

Consequência prática: mesmo que alguém contornasse o RLS e copiasse o
`content_cipher` da Alice para uma linha do Bruno, **o texto não abriria** — a
AAD não bateria. É a criptografia reforçando o isolamento que o banco já
garante. Está testado em
[`tests/test_crypto.py::test_nota_copiada_para_outro_usuario_nao_abre`](../tests/test_crypto.py).

### Formato do envelope

```
Base64( nonce[12 bytes] ‖ ciphertext ‖ tag[16 bytes] )
```

O nonce é sorteado a cada operação de escrita (`os.urandom`). Reutilizar nonce
com a mesma chave é a falha catastrófica clássica do GCM — por isso ele nunca
é derivado nem contado aqui, sempre aleatório. Efeito colateral visível: cifrar
o mesmo texto duas vezes produz saídas diferentes.

---

## 3. As duas senhas do sistema

Elas fazem coisas diferentes e é importante não confundi-las:

| | Senha da conta | Passphrase do diário |
|---|---|---|
| Para que serve | autenticar no Supabase Auth | derivar a chave que abre as notas |
| Vai para o servidor? | sim (o GoTrue guarda o hash) | **nunca** |
| Se for esquecida | "esqueci minha senha" por e-mail | não há recuperação possível |
| Se vazar | o atacante entra na conta e vê **texto cifrado** | sozinha não serve: ainda é preciso passar pelo RLS |

Nenhuma das duas, isolada, entrega o diário. É essa separação que faz o modelo
ser de conhecimento zero em relação ao servidor.

---

## 4. O que existe no banco

Uma linha real de `public.notes`, como o administrador a enxerga:

```json
{
  "id": "76399abd-9281-4afb-8189-dc0f594330ca",
  "user_id": "d342865c-f4b9-4806-85e6-7dc4576a64e5",
  "title_cipher": "QZSnoTXufji93027sDgrU0B0eCdcaYYcU5qe9kbsktyneRR+6dCze6WfT2pTuAl/vden0707h1fu",
  "content_cipher": "OPVkvM95v4vCH+z/9qXxKoY3xy8g2mW8LdWJsNVQzCydtbcRFfnaBwOUUs6OLGBu9LW1v1CYWLoJ…",
  "crypto_version": 1,
  "created_at": "2026-07-31T18:22:04.918Z"
}
```

Para gerar esse arquivo na sua máquina e conferir a olho:

```bash
python scripts/gerar_massa_demo.py --recriar
# grava data/amostra_cifrada.json com o que a camada de dados realmente guarda
```

O que **não** é cifrado, e por quê:

* `id`, `user_id` — o RLS precisa deles em claro para comparar;
* `created_at`, `updated_at` — ordenação e agregação por data;
* `kdf_salt` — salt é público por definição;
* `crypto_version` — permite migrar o formato criptográfico no futuro.

Isso significa que o servidor sabe *quantas* notas você tem e *quando* você
escreveu, mas não *o que* você escreveu.

---

## 5. Consequências práticas da criptografia ponta a ponta

Coisas que ficam mais difíceis — e que um projeto sério precisa admitir:

**Busca acontece no cliente.** Não há `ilike` nem índice de texto possível
sobre bytes opacos. O app baixa, decifra e filtra em memória
([`service.buscar`](../src/diario/service.py)). Para um diário pessoal
(dezenas a centenas de notas) é irrelevante; num produto com milhares de
registros por usuário, o caminho seria índice cifrado ou busca por tokens com
hash cego.

**Não há relatório do lado do servidor.** A view `minhas_notas_por_mes` agrega
*contagens*, não conteúdo — é tudo o que dá para fazer sem a chave.

**Não há recuperação de senha do diário.** Um produto real ofereceria um
código de recuperação impresso no cadastro (uma segunda cópia da DEK,
embrulhada por uma chave aleatória mostrada uma única vez ao usuário). O app
avisa isso em vermelho na criação do cofre.

---

## 6. Limitações conhecidas desta implementação

Um item de portfólio que só lista virtudes não é confiável. As duas
limitações reais:

**1. A criptografia roda no servidor Streamlit, não no navegador.** O
Streamlit executa Python no servidor: a passphrase digitada trafega até o
processo do app e a DEK vive na memória dele enquanto o cofre está aberto. O
modelo é "zero-knowledge em relação ao Supabase", não em relação a quem hospeda
o app. Em produção, a cifragem deveria acontecer no navegador (Web Crypto API,
`crypto.subtle`), com o servidor recebendo apenas o texto já cifrado — a
arquitetura de chaves aqui foi desenhada para essa migração: nada no schema
mudaria, só o local de execução do módulo `crypto`.

**2. Sem rate limiting próprio para tentativas de passphrase.** O custo do
Scrypt é a única barreira contra força bruta local. O Supabase Auth aplica
limites nas tentativas de *login*, mas o desbloqueio do cofre acontece no
cliente e não passa por ele.

---

## 7. Higiene de chaves e segredos

* `.env` está no `.gitignore`; o versionado é o `.env.example`.
* O app usa **exclusivamente** a `anon key`, que é pública por projeto — sem
  JWT de usuário, ela não abre nenhuma linha.
* A `service_role key` (com `BYPASSRLS`) nunca aparece no projeto. O app varre
  o ambiente atrás de variáveis com `SERVICE_ROLE`/`SERVICE_KEY` no nome e
  exibe alerta vermelho em tela se encontrar alguma.
* As migrations criam funções com `security invoker` e `set search_path = ''`,
  fechando a porta para sequestro de `search_path`.

---

## 8. Referências

* [Supabase — Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)
* [PostgreSQL — CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html)
* [NIST SP 800-38D — Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)
* [RFC 7914 — The scrypt KDF](https://datatracker.ietf.org/doc/html/rfc7914)
* [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
