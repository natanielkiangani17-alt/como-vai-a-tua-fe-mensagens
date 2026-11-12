import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "mensagens.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "troque-esta-chave-em-producao")


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


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "admin_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/enviar")
def enviar():
    # Honeypot simples contra bots. Não recolhe identidade.
    if request.form.get("website"):
        return redirect(url_for("index"))

    category = request.form.get("category", "").strip()
    message = request.form.get("message", "").strip()

    allowed = {
        "Pedido de oração",
        "Testemunho",
        "Pedido de ajuda",
        "Mensagem",
        "Outro",
    }

    if category not in allowed:
        flash("Escolha uma categoria válida.", "error")
        return redirect(url_for("index"))

    if len(message) < 5:
        flash("Escreva uma mensagem um pouco mais completa.", "error")
        return redirect(url_for("index"))

    if len(message) > 5000:
        flash("A mensagem é demasiado longa.", "error")
        return redirect(url_for("index"))

    db = get_db()
    db.execute(
        """
        INSERT INTO messages (category, message, status, created_at)
        VALUES (?, ?, 'Não lida', ?)
        """,
        (category, message, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()

    flash("A tua mensagem foi enviada anonimamente. Obrigado por partilhares.", "success")
    return redirect(url_for("index"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin = get_db().execute(
            "SELECT * FROM admins WHERE username = ?", (username,)
        ).fetchone()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["admin_id"] = admin["id"]
            session["admin_username"] = admin["username"]
            return redirect(url_for("admin"))

        flash("Utilizador ou palavra-passe incorretos.", "error")

    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@login_required
def admin():
    db = get_db()
    messages = db.execute(
        """
        SELECT id, category, message, status, created_at
        FROM messages
        ORDER BY id DESC
        """
    ).fetchall()

    return render_template(
        "admin.html",
        messages=messages,
        username=session.get("admin_username"),
    )


@app.post("/admin/message/<int:message_id>/status")
@login_required
def change_status(message_id):
    status = request.form.get("status", "Não lida")
    if status not in {"Não lida", "Lida", "Arquivada"}:
        status = "Não lida"

    db = get_db()
    db.execute(
        "UPDATE messages SET status = ? WHERE id = ?",
        (status, message_id),
    )
    db.commit()
    return redirect(url_for("admin"))


@app.post("/admin/message/<int:message_id>/delete")
@login_required
def delete_message(message_id):
    db = get_db()
    db.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(debug=True)
