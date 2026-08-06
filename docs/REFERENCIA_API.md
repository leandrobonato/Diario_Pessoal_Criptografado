# Referência dos módulos

Mapa do pacote `diario` para quem for estender o projeto.

---

## `diario.crypto`

Criptografia ponta a ponta. Nenhuma outra camada faz cifragem.

### Constantes

| Nome | Valor | Significado |
|---|---|---|
| `CRYPTO_VERSION` | `1` | versão do formato de envelope |
| `SCRYPT_N` / `SCRYPT_R` / `SCRYPT_P` | `2**15` / `8` / `1` | custo do KDF (~32 MB, ~100 ms) |
| `CHAVE_BYTES` | `32` | AES-256 |
| `SALT_BYTES` | `16` | salt do Scrypt |
| `NONCE_BYTES` | `12` | 96 bits, tamanho recomendado para GCM |
| `TAMANHO_MINIMO_PASSPHRASE` | `8` | validação mínima da passphrase |

### Funções

| Assinatura | O que faz |
|---|---|
| `gerar_salt() -> bytes` | salt aleatório para o Scrypt |
| `gerar_dek() -> bytes` | DEK aleatória de 256 bits |
| `derivar_kek(passphrase, salt, params=None) -> bytes` | deriva a KEK via Scrypt |
| `cifrar_texto(texto, dek, user_id) -> str` | envelope Base64 de uma nota |
| `decifrar_texto(envelope, dek, user_id) -> str` | inverso; valida a tag e a AAD |
| `embrulhar_dek(dek, kek, user_id) -> str` | cifra a DEK com a KEK |
| `desembrulhar_dek(wrapped, kek, user_id) -> bytes` | recupera a DEK |
| `criar_material_do_cofre(passphrase, user_id) -> (MaterialDoCofre, bytes)` | cofre novo |
| `abrir_cofre(passphrase, material, user_id) -> bytes` | recupera a DEK do cofre |
| `reembrulhar_dek(dek, nova_passphrase, user_id) -> MaterialDoCofre` | troca de passphrase |
| `validar_passphrase(passphrase) -> None` | levanta `ValueError` se for curta |
| `aad_nota(user_id)` / `aad_cofre(user_id)` | dados associados do AES-GCM |
| `b64e(bytes)` / `b64d(str)` | codificação Base64 |

### `MaterialDoCofre`

Dataclass imutável com o que vai para `public.diary_keys`:
`kdf_salt`, `wrapped_dek`, `kdf_params`, `crypto_version`.

---

## `diario.models`

| Tipo | Papel |
|---|---|
| `Sessao` | `user_id`, `email`, tokens |
| `NotaCifrada` | uma linha de `public.notes` como o servidor a vê |
| `Nota` | nota decifrada, pronta para exibição; tem `.resumo` |
| `CofreRemoto` | uma linha de `public.diary_keys` |

`NotaCifrada.de_dict()` e `CofreRemoto.de_dict()` constroem a partir do JSON
do PostgREST ou de uma linha do SQLite.

---

## `diario.repository`

`RepositorioDiario` é um `Protocol` (tipagem estrutural — o backend não
precisa herdar de nada).

| Método | Retorno |
|---|---|
| `sessao` (propriedade) | `Sessao \| None` |
| `criar_conta(email, senha)` | `Sessao` |
| `entrar(email, senha)` | `Sessao` |
| `sair()` | `None` |
| `obter_cofre()` | `CofreRemoto \| None` |
| `criar_cofre(material)` | `CofreRemoto` |
| `atualizar_cofre(material)` | `CofreRemoto` |
| `listar_notas()` | `list[NotaCifrada]` |
| `criar_nota(title_cipher, content_cipher)` | `NotaCifrada` |
| `atualizar_nota(id, title_cipher, content_cipher)` | `NotaCifrada` |
| `excluir_nota(id)` | `None` |
| `tentar_ler_nota(id)` | `NotaCifrada \| None` |

`criar_repositorio(configuracao=None)` devolve o backend indicado pela
configuração (import tardio: quem roda em modo demonstração não precisa ter o
pacote `supabase` instalado).

---

## `diario.service.DiarioService`

Casos de uso, independentes de interface.

| Método | Observação |
|---|---|
| `criar_conta` / `entrar` / `sair` | delegam ao repositório e zeram a DEK |
| `status_do_cofre()` | `"inexistente"`, `"bloqueado"` ou `"aberto"` |
| `criar_cofre(passphrase)` | primeiro acesso |
| `desbloquear(passphrase)` | deriva a KEK e desembrulha a DEK |
| `bloquear()` | esquece a DEK |
| `trocar_passphrase(atual, nova)` | re-embrulha a DEK; não reescreve notas |
| `listar_notas()` | `list[Nota]` já decifradas |
| `criar_nota(titulo, conteudo)` | cifra e grava |
| `atualizar_nota(id, titulo, conteudo)` | idem |
| `excluir_nota(id)` | |
| `buscar(termo)` | filtro **no cliente** (ver docs/SEGURANCA…, seção 5) |
| `tentar_ler_nota_por_id(id)` | usado pela prova de isolamento |

Propriedades: `sessao`, `logado`, `cofre_aberto`, `repositorio`.

---

## `diario.backends`

### `supabase_backend.RepositorioSupabase(url, anon_key)`

Supabase Auth + PostgREST. Traduz SQLSTATE em erro de domínio:

| SQLSTATE | Exceção |
|---|---|
| `42501` | `AcessoNegado` (recusado pelo RLS) |
| `23505` | `CofreJaExiste` (quando aplicável) |

Extra: `contar_notas_visiveis()` chama a função `public.contar_minhas_notas()`.

### `local_backend.RepositorioLocal(caminho_banco)`

SQLite para o modo demonstração. `PoliticaDeLinha` concentra o predicado
`user_id = :uid` (equivalente ao `USING`) e `validar_gravacao` (equivalente ao
`WITH CHECK`).

Extra: `contar_notas_no_banco()` — conta **todas** as linhas ignorando a
política, só para a tela de demonstração; e `fechar()`.

---

## `diario.config`

| Nome | Papel |
|---|---|
| `Configuracao` | `backend`, `supabase_url`, `supabase_anon_key`, `caminho_banco_demo` |
| `carregar_configuracao()` | lê o `.env` e resolve o backend |
| `alerta_de_chave_de_servico()` | detecta `SERVICE_ROLE`/`SERVICE_KEY` no ambiente |
| `RAIZ_PROJETO`, `PASTA_DADOS` | caminhos-base |

---

## `diario.errors`

```
DiarioError
├── CriptografiaError
│   ├── PassphraseIncorreta
│   └── EnvelopeInvalido
├── AutenticacaoError
├── SessaoInexistente
├── AcessoNegado
├── CofreInexistente
├── CofreJaExiste
└── BackendIndisponivel
```

---

## Como adicionar um campo cifrado a uma nota

1. **Migration**: nova coluna `text` + `check` de tamanho mínimo, na mesma
   linha das existentes.
2. **`models.py`**: campo em `NotaCifrada` e em `Nota`.
3. **`service.py`**: cifrar na escrita, decifrar em `_decifrar`.
4. **Backends**: incluir no payload dos dois repositórios.
5. **Testes**: um caso em `test_service.py` garantindo que o valor não aparece
   em claro na camada de dados.

Nenhuma policy precisa mudar: o isolamento é por linha, não por coluna.
