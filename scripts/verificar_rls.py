"""Auditoria de RLS contra um projeto Supabase REAL.

Enquanto os testes pgTAP rodam dentro do Postgres e os testes Python rodam no
modo demonstração, este script fecha o ciclo: ele fala com o projeto de
verdade, pela mesma API que o app usa (PostgREST + anon key), com dois
usuários reais — e tenta invadir.

Uso::

    # .env preenchido com SUPABASE_URL e SUPABASE_ANON_KEY
    python scripts/verificar_rls.py

    # ou informando as contas de teste
    python scripts/verificar_rls.py \
        --email-a alice@exemplo.test --senha-a senha123 \
        --email-b bruno@exemplo.test --senha-b senha123

Requisitos do projeto Supabase:

* migrations aplicadas (``supabase db push`` ou SQL Editor);
* confirmação de e-mail desligada em Authentication → Providers → Email
  (senão o cadastro automático das contas de teste não conclui).

Código de saída 0 = todas as verificações passaram; 1 = alguma falhou.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))

from diario.backends.supabase_backend import RepositorioSupabase  # noqa: E402
from diario.config import carregar_configuracao  # noqa: E402
from diario.errors import AcessoNegado, AutenticacaoError  # noqa: E402
from diario.service import DiarioService  # noqa: E402

PASSPHRASE_A = "auditoria-alice-2026"
PASSPHRASE_B = "auditoria-bruno-2026"


@dataclass
class Verificacao:
    descricao: str
    passou: bool
    detalhe: str = ""

    def __str__(self) -> str:
        marca = "PASSOU" if self.passou else "FALHOU"
        icone = "[ok]" if self.passou else "[!!]"
        linha = f"{icone} {marca:6}  {self.descricao}"
        return f"{linha}\n            {self.detalhe}" if self.detalhe else linha


class Auditoria:
    def __init__(self) -> None:
        self.resultados: list[Verificacao] = []

    def registrar(self, descricao: str, passou: bool, detalhe: str = "") -> None:
        verificacao = Verificacao(descricao, passou, detalhe)
        self.resultados.append(verificacao)
        print(verificacao, flush=True)

    def esperar_bloqueio(self, descricao: str, acao) -> None:
        """A ação DEVE ser barrada. Se ela funcionar, o RLS está furado."""
        try:
            resultado = acao()
        except AcessoNegado as exc:
            self.registrar(descricao, True, f"bloqueado como esperado: {exc}")
        except Exception as exc:  # noqa: BLE001 - queremos ver qualquer erro inesperado
            self.registrar(
                descricao, False, f"erro inesperado ({type(exc).__name__}): {exc}"
            )
        else:
            self.registrar(
                descricao, False, f"A OPERAÇÃO FOI PERMITIDA! Retorno: {resultado!r}"
            )

    @property
    def falhas(self) -> int:
        return sum(1 for r in self.resultados if not r.passou)


def preparar_usuario(
    url: str, chave: str, email: str, senha: str, passphrase: str
) -> DiarioService:
    """Entra (ou cadastra) e garante o cofre aberto."""
    servico = DiarioService(RepositorioSupabase(url, chave))
    try:
        servico.entrar(email, senha)
    except AutenticacaoError:
        servico.criar_conta(email, senha)

    if servico.status_do_cofre() == "inexistente":
        servico.criar_cofre(passphrase)
    else:
        servico.desbloquear(passphrase)
    return servico


def auditar(url: str, chave: str, contas: dict[str, str]) -> int:
    auditoria = Auditoria()

    print("=" * 78)
    print("AUDITORIA DE RLS —", url)
    print("=" * 78)

    alice = preparar_usuario(
        url, chave, contas["email_a"], contas["senha_a"], PASSPHRASE_A
    )
    bruno = preparar_usuario(
        url, chave, contas["email_b"], contas["senha_b"], PASSPHRASE_B
    )
    id_alice = alice.sessao.user_id  # type: ignore[union-attr]
    id_bruno = bruno.sessao.user_id  # type: ignore[union-attr]

    print(f"\nusuário A: {contas['email_a']}  ({id_alice})")
    print(f"usuário B: {contas['email_b']}  ({id_bruno})\n")

    marcador = uuid.uuid4().hex[:8]
    nota_da_alice = alice.criar_nota(
        f"Auditoria {marcador}", "Conteúdo privado da Alice."
    )
    print(f"nota criada por A: {nota_da_alice.id}\n")

    # ---------------------------------------------------------------- SELECT
    ids_visiveis = {n.id for n in bruno.listar_notas()}
    auditoria.registrar(
        "SELECT: B não enxerga a nota de A na listagem",
        nota_da_alice.id not in ids_visiveis,
        f"{len(ids_visiveis)} nota(s) visível(is) para B",
    )
    auditoria.registrar(
        "SELECT por id: a nota de A não retorna para B",
        bruno.tentar_ler_nota_por_id(nota_da_alice.id) is None,
    )

    # ---------------------------------------------------------------- UPDATE
    auditoria.esperar_bloqueio(
        "UPDATE: B não altera a nota de A",
        lambda: bruno.atualizar_nota(nota_da_alice.id, "invadido", "invadido"),
    )

    # ---------------------------------------------------------------- DELETE
    auditoria.esperar_bloqueio(
        "DELETE: B não apaga a nota de A",
        lambda: bruno.excluir_nota(nota_da_alice.id),
    )

    # ---------------------------------------------------------------- INSERT
    def inserir_forjando_dono():
        cliente = bruno.repositorio._client  # noqa: SLF001 - teste de segurança
        return (
            cliente.table("notes")
            .insert(
                {
                    "user_id": id_alice,  # forjando o dono
                    "title_cipher": "Zm9yamFkby10aXR1bG8tZGUtYXVkaXRvcmlhLTAwMDAwMDAw",
                    "content_cipher": "Zm9yamFkby1jb250ZXVkby1kZS1hdWRpdG9yaWEtMDAwMDAwMDA=",
                }
            )
            .execute()
        )

    auditoria.esperar_bloqueio(
        "INSERT: B não grava nota em nome de A (WITH CHECK)", inserir_forjando_dono
    )

    # ------------------------------------------------------------ diary_keys
    cofre_de_bruno = bruno.repositorio.obter_cofre()
    auditoria.registrar(
        "diary_keys: B só alcança o próprio cofre",
        cofre_de_bruno is not None and cofre_de_bruno.user_id == id_bruno,
    )

    # ------------------------------------------------------------- anônimo
    from supabase import create_client

    anonimo = create_client(url, chave)
    try:
        resposta = anonimo.table("notes").select("*").execute()
    except Exception as exc:  # noqa: BLE001
        auditoria.registrar(
            "anon: visitante sem login é barrado", True, f"{type(exc).__name__}: {exc}"
        )
    else:
        auditoria.registrar(
            "anon: visitante sem login é barrado",
            not resposta.data,
            f"{len(resposta.data or [])} linha(s) retornada(s)",
        )

    # ------------------------------------------------------- integridade
    ainda_intacta = alice.tentar_ler_nota_por_id(nota_da_alice.id)
    auditoria.registrar(
        "A nota de A continua intacta após as tentativas de B",
        ainda_intacta is not None
        and ainda_intacta.conteudo == "Conteúdo privado da Alice.",
    )

    # ------------------------------------------------------------- limpeza
    alice.excluir_nota(nota_da_alice.id)

    print("\n" + "=" * 78)
    total = len(auditoria.resultados)
    if auditoria.falhas:
        print(f"RESULTADO: {auditoria.falhas} de {total} verificações FALHARAM.")
    else:
        print(f"RESULTADO: todas as {total} verificações passaram.")
    print("=" * 78)
    return 1 if auditoria.falhas else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email-a", default="rls.alice@exemplo.test")
    parser.add_argument("--senha-a", default="auditoria-conta-a")
    parser.add_argument("--email-b", default="rls.bruno@exemplo.test")
    parser.add_argument("--senha-b", default="auditoria-conta-b")
    args = parser.parse_args()

    cfg = carregar_configuracao()
    if not cfg.supabase_configurado:
        print(
            "SUPABASE_URL e SUPABASE_ANON_KEY não estão definidos.\n"
            "Copie .env.example para .env e preencha antes de rodar a auditoria.",
            file=sys.stderr,
        )
        return 2

    return auditar(
        cfg.supabase_url,
        cfg.supabase_anon_key,
        {
            "email_a": args.email_a,
            "senha_a": args.senha_a,
            "email_b": args.email_b,
            "senha_b": args.senha_b,
        },
    )


if __name__ == "__main__":
    raise SystemExit(main())
