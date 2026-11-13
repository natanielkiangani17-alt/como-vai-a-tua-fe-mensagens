import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    jsonify,
)

from werkzeug.security import check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# =========================================================
# CONFIGURAÇÃO
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "mensagens.db")

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "troque-esta-chave-em-producao"
)

# Sistema de tokens usado pela aplicação Android
token_serializer = URLSafeTimedSerializer(
    app.config["SECRET_KEY"]
)


# =========================================================
# BANCO DE DADOS
# =========================================================

def get_db():

    if "db" not in g:

        g.db = sqlite3.connect(DB_PATH)

        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):

    db = g.pop("db", None)

    if db is not None:
        db.close()


# =========================================================
# LOGIN DO PAINEL WEB
# =========================================================

def login_required(view):

    @wraps(view)
    def wrapped(*args, **kwargs):

        if "admin_id" not in session:

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    return wrapped


# =========================================================
# PÁGINA PÚBLICA
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# ENVIO DE MENSAGEM ANÓNIMA
# =========================================================

@app.post("/enviar")
def enviar():

    # Proteção simples contra bots
    if request.form.get("website"):

        return redirect(
            url_for("index")
        )

    category = request.form.get(
        "category",
        ""
    ).strip()

    message = request.form.get(
        "message",
        ""
    ).strip()

    allowed = {
        "Pedido de oração",
        "Testemunho",
        "Pedido de ajuda",
        "Mensagem",
        "Outro",
    }

    if category not in allowed:

        flash(
            "Escolha uma categoria válida.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    if len(message) < 5:

        flash(
            "Escreva uma mensagem um pouco mais completa.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    if len(message) > 5000:

        flash(
            "A mensagem é demasiado longa.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    db = get_db()

    db.execute(
        """
        INSERT INTO messages
        (category, message, status, created_at)
        VALUES (?, ?, 'Não lida', ?)
        """,
        (
            category,
            message,
            datetime.now(timezone.utc).isoformat(),
        ),
    )

    db.commit()

    flash(
        "A tua mensagem foi enviada anonimamente. Obrigado por partilhares.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# LOGIN WEB
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        admin = get_db().execute(
            """
            SELECT *
            FROM admins
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if admin and check_password_hash(
            admin["password_hash"],
            password
        ):

            session.clear()

            session["admin_id"] = admin["id"]

            session["admin_username"] = admin["username"]

            return redirect(
                url_for("admin")
            )

        flash(
            "Utilizador ou palavra-passe incorretos.",
            "error"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# PAINEL ADMINISTRATIVO
# =========================================================

@app.route("/admin")
@login_required
def admin():

    db = get_db()

    messages = db.execute(
        """
        SELECT
            id,
            category,
            message,
            status,
            created_at
        FROM messages
        ORDER BY id DESC
        """
    ).fetchall()

    return render_template(
        "admin.html",
        messages=messages,
        username=session.get(
            "admin_username"
        ),
    )


# =========================================================
# ALTERAR ESTADO PELO PAINEL WEB
# =========================================================

@app.post(
    "/admin/message/<int:message_id>/status"
)
@login_required
def change_status(message_id):

    status = request.form.get(
        "status",
        "Não lida"
    )

    if status not in {
        "Não lida",
        "Lida",
        "Arquivada",
    }:

        status = "Não lida"

    db = get_db()

    db.execute(
        """
        UPDATE messages
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            message_id,
        ),
    )

    db.commit()

    return redirect(
        url_for("admin")
    )


# =========================================================
# APAGAR MENSAGEM PELO PAINEL WEB
# =========================================================

@app.post(
    "/admin/message/<int:message_id>/delete"
)
@login_required
def delete_message(message_id):

    db = get_db()

    db.execute(
        """
        DELETE FROM messages
        WHERE id = ?
        """,
        (message_id,),
    )

    db.commit()

    return redirect(
        url_for("admin")
    )


# =========================================================
# ========================= API ===========================
# =========================================================


# =========================================================
# CRIAR TOKEN
# =========================================================

def create_api_token(
    admin_id,
    username
):

    data = {
        "admin_id": admin_id,
        "username": username,
    }

    return token_serializer.dumps(
        data
    )


# =========================================================
# VALIDAR TOKEN
# =========================================================

def get_api_admin():

    authorization = request.headers.get(
        "Authorization",
        ""
    )

    if not authorization.startswith(
        "Bearer "
    ):

        return None

    token = authorization[7:].strip()

    if not token:

        return None

    try:

        data = token_serializer.loads(
            token,
            max_age=60 * 60 * 24 * 30
        )

        return data

    except (
        BadSignature,
        SignatureExpired
    ):

        return None


# =========================================================
# LOGIN DA APLICAÇÃO
# =========================================================

@app.post("/api/login")
def api_login():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        data.get(
            "password",
            ""
        )
    )

    if not username or not password:

        return jsonify({
            "success": False,
            "error": "Utilizador e palavra-passe são obrigatórios."
        }), 400

    admin = get_db().execute(
        """
        SELECT *
        FROM admins
        WHERE username = ?
        """,
        (username,),
    ).fetchone()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Credenciais inválidas."
        }), 401

    if not check_password_hash(
        admin["password_hash"],
        password
    ):

        return jsonify({
            "success": False,
            "error": "Credenciais inválidas."
        }), 401

    token = create_api_token(
        admin["id"],
        admin["username"]
    )

    return jsonify({
        "success": True,
        "token": token,
        "username": admin["username"]
    })


# =========================================================
# LISTAR MENSAGENS
# =========================================================

@app.get("/api/messages")
def api_messages():

    admin = get_api_admin()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Não autorizado."
        }), 401

    db = get_db()

    messages = db.execute(
        """
        SELECT
            id,
            category,
            message,
            status,
            created_at
        FROM messages
        ORDER BY id DESC
        """
    ).fetchall()

    result = []

    for item in messages:

        result.append({
            "id": item["id"],
            "category": item["category"],
            "message": item["message"],
            "status": item["status"],
            "created_at": item["created_at"],
        })

    return jsonify({
        "success": True,
        "messages": result
    })


# =========================================================
# ALTERAR ESTADO PELA APP
# =========================================================

@app.post(
    "/api/messages/<int:message_id>/status"
)
def api_change_status(message_id):

    admin = get_api_admin()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Não autorizado."
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status",
        "Não lida"
    )

    if status not in {
        "Não lida",
        "Lida",
        "Arquivada",
    }:

        return jsonify({
            "success": False,
            "error": "Estado inválido."
        }), 400

    db = get_db()

    db.execute(
        """
        UPDATE messages
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            message_id,
        ),
    )

    db.commit()

    return jsonify({
        "success": True
    })


# =========================================================
# APAGAR MENSAGEM PELA APP
# =========================================================

@app.delete(
    "/api/messages/<int:message_id>"
)
def api_delete_message(message_id):

    admin = get_api_admin()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Não autorizado."
        }), 401

    db = get_db()

    db.execute(
        """
        DELETE FROM messages
        WHERE id = ?
        """,
        (message_id,),
    )

    db.commit()

    return jsonify({
        "success": True
    })


# =========================================================
# INICIAR SERVIDOR
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )
