"""Gera a massa de demonstração do diário (modo local).

Cria duas contas com cofres e anotações **de verdade** — cifradas com o mesmo
código que o app usa —, de modo que dá para abrir o projeto e já ter conteúdo
na tela, além de dois usuários distintos para exercitar o isolamento.

Uso::

    python scripts/gerar_massa_demo.py            # cria em data/diario_demo.db
    python scripts/gerar_massa_demo.py --recriar  # apaga o banco antes

Artefatos gravados em ``data/`` (fora do controle de versão):

* ``diario_demo.db``      — banco SQLite do modo demonstração;
* ``amostra_cifrada.json`` — o que a camada de dados realmente guarda, para
  quem quiser conferir a olho que não há texto em claro.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))

from diario.backends.local_backend import RepositorioLocal  # noqa: E402
from diario.config import PASTA_DADOS  # noqa: E402
from diario.service import DiarioService  # noqa: E402

CONTAS = {
    "alice": {
        "email": "alice@exemplo.test",
        "senha": "senha-da-conta",
        "passphrase": "cafe-com-leite-42",
        "notas": [
            (
                "Primeiro dia do diário",
                "Resolvi voltar a escrever. Não para ninguém ler — justamente por "
                "isso escolhi um diário em que só eu tenho a chave.",
            ),
            (
                "Corrida no parque",
                "Sete quilômetros hoje, o melhor tempo do mês. O joelho reclamou no "
                "fim, mas valeu.",
            ),
            (
                "Conversa difícil no trabalho",
                "Precisei dizer não a um prazo impossível. Saí da reunião tenso, "
                "mas dormindo melhor.",
            ),
        ],
    },
    "bruno": {
        "email": "bruno@exemplo.test",
        "senha": "senha-da-conta",
        "passphrase": "montanha-azul-77",
        "notas": [
            (
                "Mudança de cidade",
                "As caixas ainda estão no corredor. A cidade nova cheira diferente.",
            ),
            (
                "Curso de fotografia",
                "Aprendi hoje que a luz das seis da tarde faz metade do trabalho.",
            ),
        ],
    },
}


def gerar(caminho_banco: Path, recriar: bool) -> None:
    if recriar and caminho_banco.exists():
        caminho_banco.unlink()
        print(f"banco anterior removido: {caminho_banco}")

    caminho_banco.parent.mkdir(parents=True, exist_ok=True)
    repositorio = RepositorioLocal(caminho_banco)
    servico = DiarioService(repositorio)

    amostra: list[dict[str, str]] = []

    for apelido, dados in CONTAS.items():
        try:
            servico.criar_conta(dados["email"], dados["senha"])
        except Exception as exc:  # conta já existe: apenas entra
            print(f"{apelido}: {exc} — entrando com a conta existente.")
            servico.entrar(dados["email"], dados["senha"])

        if servico.status_do_cofre() == "inexistente":
            servico.criar_cofre(dados["passphrase"])
        else:
            servico.desbloquear(dados["passphrase"])

        existentes = {n.titulo for n in servico.listar_notas()}
        for titulo, conteudo in dados["notas"]:
            if titulo not in existentes:
                servico.criar_nota(titulo, conteudo)

        for cifrada in repositorio.listar_notas():
            amostra.append(
                {
                    "usuario": apelido,
                    "id": cifrada.id,
                    "user_id": cifrada.user_id,
                    "title_cipher": cifrada.title_cipher,
                    "content_cipher": cifrada.content_cipher,
                }
            )

        print(
            f"{apelido}: {len(servico.listar_notas())} nota(s) — "
            f"login {dados['email']} / {dados['senha']} — "
            f"passphrase do diário: {dados['passphrase']}"
        )
        servico.sair()

    destino = caminho_banco.parent / "amostra_cifrada.json"
    destino.write_text(
        json.dumps(amostra, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print(f"\nbanco:   {caminho_banco}")
    print(f"amostra: {destino}")
    print(
        "\nAbra a amostra e procure por qualquer palavra das anotações: não há "
        "nenhuma. É o que o servidor enxerga."
    )
    repositorio.fechar()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--banco",
        type=Path,
        default=PASTA_DADOS / "diario_demo.db",
        help="caminho do banco SQLite de demonstração",
    )
    parser.add_argument(
        "--recriar", action="store_true", help="apaga o banco antes de gerar"
    )
    args = parser.parse_args()
    gerar(args.banco, args.recriar)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
