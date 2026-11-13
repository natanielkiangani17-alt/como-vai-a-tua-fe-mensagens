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

# =========================================================
# INICIALIZAÇÃO AUTOMÁTICA DO BANCO DE DADOS
# =========================================================

def init_db():

    db = sqlite3.connect(DB_PATH)

    db.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Não lida',
            created_at TEXT NOT NULL
        )
    """)

    db.commit()
    db.close()


init_db()


# =========================================================
# SISTEMA DE TOKENS DA APP ANDROID
# =========================================================

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
# PÁGINA PRINCIPAL
# =========================================================

@app.route("/")
def index():

    return render_template("index.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
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
            (username,)
        ).fetchone()

        if admin and check_password_hash(
            admin["password_hash"],
            password
        ):

            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]

            return redirect(
                url_for("admin")
            )

        flash(
            "Utilizador ou palavra-passe incorretos.",
            "error"
        )

    return render_template("login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
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

    messages = get_db().execute(
        """
        SELECT *
        FROM messages
        ORDER BY id DESC
        """
    ).fetchall()

    return render_template(
        "admin.html",
        messages=messages
    )


# =========================================================
# API - LOGIN DA APP ANDROID
# =========================================================

@app.route("/api/login", methods=["POST"])
def api_login():

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get("username", "")
    ).strip()

    password = str(
        data.get("password", "")
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
        (username,)
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

    token = token_serializer.dumps({
        "admin_id": admin["id"],
        "username": admin["username"]
    })

    return jsonify({
        "success": True,
        "token": token,
        "username": admin["username"]
    })


# =========================================================
# AUTENTICAÇÃO DA API
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

    token = authorization[
        7:
    ].strip()

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
# API - LISTAR MENSAGENS
# =========================================================

@app.route("/api/messages", methods=["GET"])
def api_messages():

    admin = get_api_admin()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Não autorizado."
        }), 401

    messages = get_db().execute(
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

    for message in messages:

        result.append({
            "id": message["id"],
            "category": message["category"],
            "message": message["message"],
            "status": message["status"],
            "created_at": message["created_at"]
        })

    return jsonify({
        "success": True,
        "messages": result
    })


# =========================================================
# API - ALTERAR STATUS DA MENSAGEM
# =========================================================

@app.route(
    "/api/messages/<int:message_id>/status",
    methods=["POST"]
)
def api_message_status(message_id):

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
        ""
    )

    allowed_statuses = [
        "Não lida",
        "Lida",
        "Arquivada"
    ]

    if status not in allowed_statuses:

        return jsonify({
            "success": False,
            "error": "Status inválido."
        }), 400

    db = get_db()

    cursor = db.execute(
        """
        UPDATE messages
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            message_id
        )
    )

    db.commit()

    if cursor.rowcount == 0:

        return jsonify({
            "success": False,
            "error": "Mensagem não encontrada."
        }), 404

    return jsonify({
        "success": True,
        "message": "Status atualizado."
    })


# =========================================================
# API - APAGAR MENSAGEM
# =========================================================

@app.route(
    "/api/messages/<int:message_id>",
    methods=["DELETE"]
)
def api_delete_message(message_id):

    admin = get_api_admin()

    if not admin:

        return jsonify({
            "success": False,
            "error": "Não autorizado."
        }), 401

    db = get_db()

    cursor = db.execute(
        """
        DELETE FROM messages
        WHERE id = ?
        """,
        (message_id,)
    )

    db.commit()

    if cursor.rowcount == 0:

        return jsonify({
            "success": False,
            "error": "Mensagem não encontrada."
        }), 404

    return jsonify({
        "success": True,
        "message": "Mensagem apagada."
    })


# =========================================================
# RECEBER NOVA MENSAGEM ANÓNIMA
# =========================================================

@app.route(
    "/enviar",
    methods=["POST"]
)
def enviar():

    category = request.form.get(
        "category",
        ""
    ).strip()

    message = request.form.get(
        "message",
        ""
    ).strip()

    if not category or not message:

        flash(
            "Preencha todos os campos.",
            "error"
        )

        return redirect(
            url_for("index")
        )

    created_at = datetime.now(
        timezone.utc
    ).isoformat()

    db = get_db()

    db.execute(
        """
        INSERT INTO messages (
            category,
            message,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            category,
            message,
            "Não lida",
            created_at
        )
    )

    db.commit()

    flash(
        "A tua mensagem foi enviada com sucesso.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# EXECUTAR LOCALMENTE
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
