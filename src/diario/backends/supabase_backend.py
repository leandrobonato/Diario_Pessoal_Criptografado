"""Backend real: Supabase Auth + PostgREST sobre PostgreSQL com RLS.

Aqui o app é deliberadamente ingênuo: ele **não** escreve ``where user_id =
...`` em lugar nenhum. Quem garante o isolamento é o banco, através das
policies criadas em ``supabase/migrations/20260731120100_rls_policies.sql``.

Essa é a diferença entre "filtrar por usuário" e "isolar por usuário":

* filtrar no app  → um ``WHERE`` esquecido, um endpoint novo mal escrito ou um
  cliente que fala direto com a API já vazam o dado;
* isolar no banco → o vazamento teria que atravessar o Postgres, que aplica a
  policy em toda e qualquer consulta, venha ela de onde vier.

O único segredo que este módulo conhece é a **anon key**, que é pública por
projeto e inútil sozinha: sem um JWT de usuário válido, as policies não
liberam nenhuma linha.
"""

from __future__ import annotations

from typing import Any

from ..crypto import MaterialDoCofre
from ..errors import (
    AcessoNegado,
    AutenticacaoError,
    BackendIndisponivel,
    CofreJaExiste,
    SessaoInexistente,
)
from ..models import CofreRemoto, NotaCifrada, Sessao

#: SQLSTATE devolvido pelo Postgres quando o WITH CHECK de uma policy recusa a
#: gravação ("new row violates row-level security policy").
SQLSTATE_RLS = "42501"

#: SQLSTATE de violação de unicidade (cofre duplicado).
SQLSTATE_UNIQUE = "23505"


class RepositorioSupabase:
    """Implementa :class:`diario.repository.RepositorioDiario` sobre o Supabase."""

    nome = "Supabase (PostgreSQL + RLS)"
    remoto = True

    def __init__(self, url: str, anon_key: str) -> None:
        if not url or not anon_key:
            raise BackendIndisponivel(
                "SUPABASE_URL e SUPABASE_ANON_KEY precisam estar definidos "
                "(veja o .env.example)."
            )
        try:
            from supabase import create_client
        except ImportError as exc:  # pragma: no cover - depende do ambiente
            raise BackendIndisponivel(
                "Pacote 'supabase' não instalado. Rode: pip install -r requirements.txt"
            ) from exc

        self._client = create_client(url, anon_key)
        self._sessao: Sessao | None = None

    # ------------------------------------------------------------------ #
    # Autenticação
    # ------------------------------------------------------------------ #
    @property
    def sessao(self) -> Sessao | None:
        return self._sessao

    def criar_conta(self, email: str, senha: str) -> Sessao:
        resposta = self._client.auth.sign_up({"email": email, "password": senha})
        if resposta.session is None:
            # Acontece quando a confirmação de e-mail está ligada no projeto.
            raise AutenticacaoError(
                "Conta criada, mas é preciso confirmar o e-mail antes de entrar. "
                "Em projetos de teste, desligue 'Confirm email' em "
                "Authentication → Providers → Email."
            )
        return self._registrar_sessao(resposta)

    def entrar(self, email: str, senha: str) -> Sessao:
        try:
            resposta = self._client.auth.sign_in_with_password(
                {"email": email, "password": senha}
            )
        except Exception as exc:  # a lib envolve o erro HTTP do GoTrue
            raise AutenticacaoError(f"Não foi possível entrar: {exc}") from exc
        if resposta.session is None:
            raise AutenticacaoError("E-mail ou senha inválidos.")
        return self._registrar_sessao(resposta)

    def sair(self) -> None:
        try:
            self._client.auth.sign_out()
        finally:
            self._sessao = None

    def _registrar_sessao(self, resposta: Any) -> Sessao:
        """Guarda a sessão e amarra o JWT do usuário às chamadas do PostgREST.

        É este token que faz ``auth.uid()`` devolver o id do usuário dentro do
        Postgres — ou seja, é ele que dá vida às policies.
        """
        sessao = resposta.session
        self._client.postgrest.auth(sessao.access_token)
        self._sessao = Sessao(
            user_id=resposta.user.id,
            email=resposta.user.email or "",
            access_token=sessao.access_token,
            refresh_token=sessao.refresh_token,
        )
        return self._sessao

    def _exigir_sessao(self) -> Sessao:
        if self._sessao is None:
            raise SessaoInexistente("Nenhum usuário autenticado nesta sessão.")
        return self._sessao

    # ------------------------------------------------------------------ #
    # Cofre de chaves
    # ------------------------------------------------------------------ #
    def obter_cofre(self) -> CofreRemoto | None:
        self._exigir_sessao()
        dados = self._executar(
            lambda: self._client.table("diary_keys").select("*").limit(1).execute()
        )
        return CofreRemoto.de_dict(dados[0]) if dados else None

    def criar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        self._exigir_sessao()
        # user_id omitido de propósito: quem preenche é o DEFAULT auth.uid().
        payload = {
            "kdf_salt": material.kdf_salt,
            "kdf_params": material.kdf_params,
            "wrapped_dek": material.wrapped_dek,
            "crypto_version": material.crypto_version,
        }
        dados = self._executar(
            lambda: self._client.table("diary_keys").insert(payload).execute(),
            duplicado=CofreJaExiste("Este usuário já possui um cofre."),
        )
        return CofreRemoto.de_dict(dados[0])

    def atualizar_cofre(self, material: MaterialDoCofre) -> CofreRemoto:
        sessao = self._exigir_sessao()
        payload = {
            "kdf_salt": material.kdf_salt,
            "kdf_params": material.kdf_params,
            "wrapped_dek": material.wrapped_dek,
            "crypto_version": material.crypto_version,
        }
        dados = self._executar(
            lambda: self._client.table("diary_keys")
            .update(payload)
            .eq("user_id", sessao.user_id)
            .execute()
        )
        if not dados:
            raise AcessoNegado("Cofre inacessível para atualização.")
        return CofreRemoto.de_dict(dados[0])

    # ------------------------------------------------------------------ #
    # Notas
    # ------------------------------------------------------------------ #
    def listar_notas(self) -> list[NotaCifrada]:
        self._exigir_sessao()
        # Repare: nenhum filtro por usuário. O RLS já devolve só o que é meu.
        dados = self._executar(
            lambda: self._client.table("notes")
            .select("*")
            .order("created_at", desc=True)
            .execute()
        )
        return [NotaCifrada.de_dict(linha) for linha in dados]

    def criar_nota(self, title_cipher: str, content_cipher: str) -> NotaCifrada:
        self._exigir_sessao()
        payload = {"title_cipher": title_cipher, "content_cipher": content_cipher}
        dados = self._executar(
            lambda: self._client.table("notes").insert(payload).execute()
        )
        return NotaCifrada.de_dict(dados[0])

    def atualizar_nota(
        self, nota_id: str, title_cipher: str, content_cipher: str
    ) -> NotaCifrada:
        self._exigir_sessao()
        payload = {"title_cipher": title_cipher, "content_cipher": content_cipher}
        dados = self._executar(
            lambda: self._client.table("notes")
            .update(payload)
            .eq("id", nota_id)
            .execute()
        )
        if not dados:
            # O RLS não distingue "não existe" de "não é sua" — e nós também não.
            raise AcessoNegado("Nota inexistente ou pertencente a outro usuário.")
        return NotaCifrada.de_dict(dados[0])

    def excluir_nota(self, nota_id: str) -> None:
        self._exigir_sessao()
        dados = self._executar(
            lambda: self._client.table("notes").delete().eq("id", nota_id).execute()
        )
        if not dados:
            raise AcessoNegado("Nota inexistente ou pertencente a outro usuário.")

    def tentar_ler_nota(self, nota_id: str) -> NotaCifrada | None:
        self._exigir_sessao()
        dados = self._executar(
            lambda: self._client.table("notes").select("*").eq("id", nota_id).execute()
        )
        return NotaCifrada.de_dict(dados[0]) if dados else None

    # ------------------------------------------------------------------ #
    # Diagnóstico
    # ------------------------------------------------------------------ #
    def contar_notas_visiveis(self) -> int:
        """Usa a função ``public.contar_minhas_notas()`` (security invoker)."""
        resposta = self._client.rpc("contar_minhas_notas", {}).execute()
        return int(resposta.data or 0)

    # ------------------------------------------------------------------ #
    # Tratamento de erros do PostgREST
    # ------------------------------------------------------------------ #
    @staticmethod
    def _executar(chamada, duplicado: Exception | None = None) -> list[dict[str, Any]]:
        """Executa a chamada e traduz o erro do PostgREST em erro de domínio."""
        try:
            resposta = chamada()
        except Exception as exc:
            codigo = getattr(exc, "code", None) or (
                exc.args[0].get("code") if exc.args and isinstance(exc.args[0], dict) else None
            )
            if codigo == SQLSTATE_RLS:
                raise AcessoNegado(
                    "Bloqueado pelo RLS: a linha não pertence ao usuário autenticado."
                ) from exc
            if codigo == SQLSTATE_UNIQUE and duplicado is not None:
                raise duplicado from exc
            raise
        return list(resposta.data or [])
