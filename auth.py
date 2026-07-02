"""Autenticação e sessão do painel.

Modelo simples de usuário único (admin), adequado a um painel operacional
interno. Não há cadastro de usuários; as credenciais vêm da configuração:

  - `settings.admin_user`            → nome de usuário esperado.
  - `settings.admin_password_hash`   → hash da senha (preferencial). Suporta
                                        bcrypt e pbkdf2_sha256 via passlib.
  - `settings.admin_password_plain`  → senha em texto puro (SÓ para dev; emite
                                        aviso no stderr quando usada).

A sessão é um cookie assinado (itsdangerous) contendo apenas o nome de usuário.
A assinatura garante integridade; `max_age` garante expiração. O cookie é
`HttpOnly` + `SameSite=Lax`, e `Secure` quando `settings.cookie_secure`.

Nada aqui inicia servidor/poller no import. O bloco `__main__` oferece um CLI
para gerar o hash de senha para o `.env`:

    python auth.py <senha>
"""
from __future__ import annotations

import hmac
import sys

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from passlib.context import CryptContext
from starlette.requests import Request

from config import settings

# ---------------------------------------------------------------------------
# Hashing de senha
# ---------------------------------------------------------------------------
#
# bcrypt é o esquema preferido para novos hashes. Usamos a biblioteca `bcrypt`
# diretamente (e não o backend bcrypt do passlib) de propósito: o passlib 1.7.4
# lê `bcrypt.__about__.__version__`, atributo removido no bcrypt >= 4.1, o que
# quebra a geração/verificação com as versões atuais. Chamar o `bcrypt`
# diretamente evita esse acoplamento frágil.
#
# O passlib fica reservado apenas para VERIFICAR hashes pbkdf2_sha256 (stdlib,
# sem backend externo), garantindo compatibilidade caso o hash no `.env` tenha
# sido gerado nesse formato.
_pbkdf2_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# O bcrypt trunca silenciosamente senhas com mais de 72 bytes; truncamos
# explicitamente (mesmo comportamento efetivo) para evitar o ValueError que o
# bcrypt >= 4.1 levanta com entradas maiores.
_BCRYPT_MAX_BYTES = 72


def _bcrypt_bytes(pw: str) -> bytes:
    """Codifica a senha em bytes, truncando em 72 bytes (limite do bcrypt)."""
    return pw.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(pw: str) -> str:
    """Gera um hash bcrypt para a senha informada (para o `.env`).

    Retorna a string de hash no formato modular-crypt (ex.: `$2b$...`).
    """
    hashed = bcrypt.hashpw(_bcrypt_bytes(pw), bcrypt.gensalt())
    return hashed.decode("ascii")


def _verify_password(pw: str, stored_hash: str) -> bool:
    """Verifica a senha contra o hash armazenado.

    Aceita hashes bcrypt (`$2a$`/`$2b$`/`$2y$`) e pbkdf2_sha256
    (`$pbkdf2-sha256$`). Nunca levanta exceção: um hash inválido/corrompido ou
    esquema desconhecido simplesmente resulta em `False`.
    """
    if not stored_hash:
        return False
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(_bcrypt_bytes(pw), stored_hash.encode("ascii"))
        except Exception:
            return False
    # Demais formatos (pbkdf2_sha256) ficam a cargo do passlib.
    try:
        return _pbkdf2_context.verify(pw, stored_hash)
    except Exception:
        # Hash malformado, esquema desconhecido ou backend indisponível.
        return False


# ---------------------------------------------------------------------------
# Serializer de sessão (cookie assinado)
# ---------------------------------------------------------------------------

# Namespace ("salt") fixo para separar este cookie de outros usos do mesmo
# segredo. O segredo em si vem de settings.app_secret.
_SESSION_SALT = "painel-crowdsec.session.v1"

_serializer = URLSafeTimedSerializer(settings.app_secret, salt=_SESSION_SALT)


def _make_token(username: str) -> str:
    """Serializa e assina o nome de usuário em um token de cookie."""
    return _serializer.dumps({"u": username})


def _read_token(token: str) -> str | None:
    """Valida assinatura + expiração e devolve o usuário, ou None se inválido."""
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=settings.session_max_age)
    except (SignatureExpired, BadSignature):
        return None
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    user = data.get("u")
    if not isinstance(user, str) or not user:
        return None
    return user


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def verify_login(username: str, password: str) -> bool:
    """Confere usuário + senha contra a configuração.

    A comparação do nome de usuário é feita em tempo constante para não vazar
    o `admin_user` por temporização. A senha é verificada preferencialmente
    contra `admin_password_hash`; se este estiver vazio mas houver
    `admin_password_plain`, faz fallback (dev) com aviso no stderr.
    """
    username = username or ""
    password = password or ""

    # Compara o nome de usuário em tempo constante.
    expected_user = settings.admin_user or ""
    user_ok = hmac.compare_digest(username.encode("utf-8"), expected_user.encode("utf-8"))

    if settings.admin_password_hash:
        pass_ok = _verify_password(password, settings.admin_password_hash)
    elif settings.admin_password_plain:
        # Fallback de desenvolvimento: comparação em tempo constante do texto.
        print(
            "AVISO: usando ADMIN_PASSWORD (texto puro). Defina ADMIN_PASSWORD_HASH "
            "para produção — gere com: python auth.py <senha>",
            file=sys.stderr,
        )
        pass_ok = hmac.compare_digest(
            password.encode("utf-8"),
            settings.admin_password_plain.encode("utf-8"),
        )
    else:
        # Sem hash e sem senha em texto: login impossível.
        print(
            "AVISO: nenhuma credencial configurada (ADMIN_PASSWORD_HASH e "
            "ADMIN_PASSWORD vazios); login sempre falhará.",
            file=sys.stderr,
        )
        pass_ok = False

    # `and` não curto-circuita aqui de forma sensível pois ambos já foram
    # calculados; evita revelar qual campo falhou.
    return bool(user_ok and pass_ok)


# ---------------------------------------------------------------------------
# Cookie de sessão
# ---------------------------------------------------------------------------

def create_session_cookie(response: object, username: str) -> None:
    """Grava o cookie de sessão assinado na `Response` do FastAPI.

    `response` é tipada como `object` para não impor import do FastAPI aqui;
    espera-se um objeto com o método `set_cookie(...)` (fastapi/starlette
    Response).
    """
    token = _make_token(username)
    response.set_cookie(  # type: ignore[attr-defined]
        key=settings.session_cookie,
        value=token,
        max_age=settings.session_max_age,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )


def clear_session_cookie(response: object) -> None:
    """Remove o cookie de sessão (logout)."""
    response.delete_cookie(  # type: ignore[attr-defined]
        key=settings.session_cookie,
        path="/",
    )


# ---------------------------------------------------------------------------
# Leitura do usuário atual / dependência FastAPI
# ---------------------------------------------------------------------------

def current_user(request: object) -> str | None:
    """Devolve o usuário autenticado a partir do cookie, ou None.

    NÃO levanta exceção — usado por app.py para decidir entre servir HTML ou
    redirecionar para a tela de login. `request` deve expor `.cookies` (um
    mapeamento nome→valor), como o `Request` do FastAPI/Starlette.
    """
    cookies = getattr(request, "cookies", None)
    if not cookies:
        return None
    token = cookies.get(settings.session_cookie)
    if not token:
        return None
    return _read_token(token)


def require_auth(request: Request) -> str:
    """Dependência FastAPI: exige sessão válida e devolve o nome de usuário.

    Uso:
        @app.get("/api/algo")
        def handler(user: str = Depends(require_auth)):
            ...

    O parâmetro é anotado como `Request` para que o FastAPI injete a requisição
    automaticamente (e não a interprete como parâmetro de query).

    Levanta HTTPException 401 (JSON `{"detail": "nao autenticado"}`) quando não
    há sessão válida. As rotas HTML tratam o redirecionamento por conta própria
    usando `current_user`.
    """
    user = current_user(request)
    if user is None:
        # Import local para não acoplar o import-time deste módulo ao FastAPI.
        from fastapi import HTTPException

        raise HTTPException(status_code=401, detail="nao autenticado")
    return user


# ---------------------------------------------------------------------------
# CLI: geração de hash de senha para o .env
# ---------------------------------------------------------------------------

def _cli_hash(argv: list[str]) -> int:
    """Implementa `python auth.py <senha>` — imprime um hash bcrypt."""
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print("Uso: python auth.py <senha>", file=sys.stderr)
        print(
            "Gera um hash bcrypt para colar em ADMIN_PASSWORD_HASH no .env.",
            file=sys.stderr,
        )
        return 2

    password = argv[0]
    try:
        hashed = hash_password(password)
    except Exception as exc:
        # Tipicamente: pacote bcrypt ausente. Orienta a instalação.
        print(
            "ERRO: não foi possível gerar o hash bcrypt. Verifique se o pacote "
            "está instalado (pip install bcrypt).",
            file=sys.stderr,
        )
        print(f"Detalhe: {exc}", file=sys.stderr)
        return 1

    # Somente o hash vai para o stdout, para permitir captura em scripts:
    #   ADMIN_PASSWORD_HASH=$(python auth.py 'minhasenha')
    print(hashed)
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_hash(sys.argv[1:]))
