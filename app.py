import os
import sqlite3
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "cle_secrete_pressing_saas_ultra_securisee"
DATABASE = "pressing_saas.db"

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ADMIN_USER = "admin"
ADMIN_PASS = "admin1234"
ADMIN_PHONE = "0768356435"
ADMIN_PHONE_INT = "2250768356435"


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""
            CREATE TABLE IF NOT EXISTS pressings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom_pressing TEXT NOT NULL,
                nom_gerant TEXT NOT NULL,
                telephone TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                sub_expires_at DATETIME NOT NULL,
                pass_urgence_until DATETIME,
                pass_demande INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            db.execute(
                "ALTER TABLE pressings ADD COLUMN pass_demande INTEGER DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass

        db.execute("""
            CREATE TABLE IF NOT EXISTS config (
                cle TEXT PRIMARY KEY,
                valeur TEXT
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pressing_id INTEGER NOT NULL,
                nom TEXT NOT NULL,
                telephone TEXT NOT NULL,
                FOREIGN KEY(pressing_id) REFERENCES pressings(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS commandes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pressing_id INTEGER NOT NULL,
                client_id INTEGER NOT NULL,
                code_ticket TEXT NOT NULL,
                montant_total REAL DEFAULT 0,
                statut_paiement TEXT DEFAULT 'Non Payé',
                mode_paiement TEXT DEFAULT 'Non spécifié',
                statut_livraison TEXT DEFAULT 'En attente',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(pressing_id) REFERENCES pressings(id) ON DELETE CASCADE,
                FOREIGN KEY(client_id) REFERENCES clients(id)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                commande_id INTEGER NOT NULL,
                designation TEXT NOT NULL,
                couleur TEXT,
                etat_initial TEXT,
                emplacement_rayon TEXT NOT NULL,
                photo TEXT,
                prix REAL DEFAULT 0,
                statut TEXT DEFAULT 'Reçu',
                FOREIGN KEY(commande_id) REFERENCES commandes(id) ON DELETE CASCADE
            )
        """)
        maint = db.execute(
            "SELECT valeur FROM config WHERE cle = 'maintenance'"
        ).fetchone()
        if not maint:
            db.execute(
                "INSERT INTO config (cle, valeur) VALUES ('maintenance', '0')"
            )
        db.commit()


def check_maintenance():
    db = get_db()
    res = db.execute(
        "SELECT valeur FROM config WHERE cle = 'maintenance'"
    ).fetchone()
    return res and res["valeur"] == "1"


# --- ANTI-CACHE NAVIGATEUR ---
@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    return response


# --- INTERCEPTATION GLOBALE ---
@app.before_request
def verifier_maintenance_globale():
    allowed_routes = [
        "page_maintenance",
        "demander_pass_urgence",
        "suggere_feature",
        "admin_login",
        "admin_dashboard",
        "admin_toggle_maintenance",
        "admin_valider_pass",
        "admin_prolonger",
        "admin_reduire",
        "admin_bloquer",
        "login",
        "register",
        "logout",
        "uploaded_file",
        "static",
    ]

    endpoint = request.endpoint

    if endpoint in allowed_routes or (
        endpoint and endpoint.startswith("admin_")
    ):
        return

    if check_maintenance() and not session.get("is_admin"):
        if session.get("pressing_id"):
            db = get_db()
            pressing = db.execute(
                "SELECT pass_urgence_until FROM pressings WHERE id = ?",
                (session["pressing_id"],),
            ).fetchone()

            if pressing and pressing["pass_urgence_until"]:
                try:
                    dt_pass = datetime.strptime(
                        pressing["pass_urgence_until"], "%Y-%m-%d %H:%M:%S"
                    )
                    if datetime.now() < dt_pass:
                        return
                except ValueError:
                    pass

        return redirect(url_for("page_maintenance"))


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "pressing_id" not in session:
            return redirect(url_for("login"))

        db = get_db()
        pressing = db.execute(
            "SELECT * FROM pressings WHERE id = ?", (session["pressing_id"],)
        ).fetchone()

        if not pressing:
            session.clear()
            return redirect(url_for("login"))

        date_expiration = datetime.strptime(
            pressing["sub_expires_at"], "%Y-%m-%d %H:%M:%S"
        )
        if datetime.now() > date_expiration:
            return redirect(url_for("abonnement_expire"))

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)

    return decorated_function


HTML_HEADER = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Au Pressing SaaS</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #eef2f5; color: #333; }
        .navbar { background: #0056b3; color: white; padding: 15px; text-align: center; font-size: 1.2rem; font-weight: bold; }
        .nav-admin { background: #111827; }
        .container { padding: 15px; max-width: 850px; margin: 0 auto; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 20px; }
        .item-box { background: #f8f9fa; border: 1px solid #ddd; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
        input, select, button { width: 100%; padding: 12px; margin: 6px 0 12px 0; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }
        button { background: #28a745; color: white; border: none; font-size: 1rem; font-weight: bold; cursor: pointer; border-radius: 6px; }
        .btn-add { background: #007bff; margin-bottom: 15px; }
        .btn-danger { background: #dc3545; }
        .btn-warning { background: #ffc107; color: #333; }
        .btn-secondary { background: #6c757d; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border: 1px solid #eee; padding: 10px; text-align: left; font-size: 0.85rem; }
        th { background: #f8f9fa; }
        .img-thumb { width: 60px; height: 60px; object-fit: cover; border-radius: 5px; border: 1px solid #ccc; }
        .alert { background: #d4edda; color: #155724; padding: 10px; border-radius: 6px; margin-bottom: 15px; }
        .badge { padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: white; }
        .badge-success { background: #28a745; }
        .badge-warning { background: #ffc107; color: #333; }
        .payment-box { background: #e0f2fe; border: 1px solid #bae6fd; padding: 15px; border-radius: 8px; margin: 15px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="navbar {{ 'nav-admin' if session.get('is_admin') else '' }}">
        🧺 Au Pressing SaaS {{ '👑 (SUPER-ADMIN)' if session.get('is_admin') else '' }}
    </div>
    <div class="container">
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}
              <div class="alert">{{ msg }}</div>
            {% endfor %}
          {% endif %}
        {% endwith %}
"""

HTML_FOOTER = """
    </div>
</body>
</html>
"""


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# --- PAGE DE MAINTENANCE ---
@app.route("/maintenance")
def page_maintenance():
    db = get_db()
    demande_active = False

    if session.get("pressing_id"):
        p = db.execute(
            "SELECT pass_demande FROM pressings WHERE id = ?",
            (session["pressing_id"],),
        ).fetchone()
        if p and p["pass_demande"] == 1:
            demande_active = True

    content = """
        <div class="card" style="text-align: center; max-width: 500px; margin: 0 auto;">
            <div style="font-size: 3rem; margin-bottom: 10px;">🛠️</div>
            <h2 style="color: #d97706; margin-top: 0;">Maintenance Système</h2>
            <p style="color: #555;">Une maintenance est en cours. Seuls les comptes autorisés peuvent accéder au système.</p>
            
            <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

            <h3>⚡ Pass Accès Urgence (1 000 FCFA / 2h)</h3>
            <p><small>Faites le transfert Wave ou Orange Money au numéro ci-dessous :</small></p>

            <div class="payment-box">
                <p style="margin: 5px 0; font-size:0.85rem;">📱 Numéro de dépôt :</p>
                <div style="font-size: 1.8rem; font-weight: bold; color: #0056b3; margin: 5px 0;">""" + ADMIN_PHONE + """</div>
                <button type="button" id="btnCopy" onclick="copierNumero('""" + ADMIN_PHONE + """')" style="background: #007bff; padding: 8px;">📋 Copier le numéro</button>
            </div>

            {% if demande_active %}
                <div style="background:#fef3c7; color:#92400e; padding:12px; border-radius:6px; margin-bottom:15px; font-weight:bold;">
                    ⏳ Demande envoyée ! En attente de confirmation administrateur...
                </div>
            {% else %}
                <div style="background: #f8f9fa; border: 1px solid #ddd; padding: 15px; border-radius: 8px; text-align: left;">
                    <h4 style="margin-top:0;">Indiquez votre numéro après paiement :</h4>
                    <form action="/demander-pass-urgence" method="POST">
                        <input type="text" name="telephone" placeholder="Votre N° de Téléphone (ex: 0701020304)" required style="margin-bottom:8px;">
                        <button type="submit" style="background: #28a745; font-size: 0.95rem; padding: 12px;">✅ Confirmer mon paiement à l'Admin</button>
                    </form>
                </div>
            {% endif %}

            <br>
            <a href="/logout" style="color: #dc3545; font-size: 0.9rem;">Se déconnecter</a>
        </div>

        <script>
            function copierNumero(tel) {
                navigator.clipboard.writeText(tel).then(() => {
                    const btn = document.getElementById('btnCopy');
                    btn.innerText = "✅ Numéro Copié !";
                    btn.style.background = "#28a745";
                    setTimeout(() => {
                        btn.innerText = "📋 Copier le numéro";
                        btn.style.background = "#007bff";
                    }, 3000);
                }).catch(() => {
                    alert("Numéro : " + tel);
                });
            }
        </script>
    """
    return render_template_string(
        HTML_HEADER + content + HTML_FOOTER, demande_active=demande_active
    )


@app.route("/demander-pass-urgence", methods=["POST"])
def demander_pass_urgence():
    telephone = request.form.get("telephone", "").strip()

    db = get_db()
    pressing = db.execute(
        "SELECT id FROM pressings WHERE telephone = ?", (telephone,)
    ).fetchone()

    if pressing:
        db.execute(
            "UPDATE pressings SET pass_demande = 1 WHERE id = ?",
            (pressing["id"],),
        )
        db.commit()
        session["pressing_id"] = pressing["id"]
        flash(
            "📩 Demande envoyée ! L'Administrateur a été notifié et débloquera votre compte sous peu."
        )
    else:
        if session.get("pressing_id"):
            db.execute(
                "UPDATE pressings SET pass_demande = 1 WHERE id = ?",
                (session["pressing_id"],),
            )
            db.commit()
            flash(
                "📩 Demande transmise à l'Administrateur pour validation."
            )
        else:
            flash(
                "❌ Aucun compte pressing trouvé avec ce numéro. Vérifiez la saisie."
            )

    return redirect(url_for("page_maintenance"))


@app.route("/suggere-feature", methods=["POST"])
def suggere_feature():
    flash("Merci ! Votre suggestion a été transmise.")
    return redirect(url_for("page_maintenance"))


# --- DASHBOARD ADMIN ---
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if (
            request.form["username"] == ADMIN_USER
            and request.form["password"] == ADMIN_PASS
        ):
            session.clear()
            session["is_admin"] = True
            return redirect(url_for("admin_dashboard"))
        flash("Identifiants Administrateur incorrects.")

    content = """
        <div class="card">
            <h2>👑 Connexion Super-Administrateur</h2>
            <form method="POST">
                <input type="text" name="username" required placeholder="Nom d'utilisateur">
                <input type="password" name="password" required placeholder="Mot de passe">
                <button type="submit" style="background:#111827;">Accéder au Panel Admin</button>
            </form>
        </div>
    """
    return render_template_string(HTML_HEADER + content + HTML_FOOTER)


@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()
    pressings = db.execute(
        "SELECT * FROM pressings ORDER BY pass_demande DESC, id DESC"
    ).fetchall()
    maint = check_maintenance()

    content = """
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <h2>Gestion des Abonnés Pressings</h2>
            <a href="/logout"><button class="btn-danger" style="width:auto; padding:8px 15px;">Déconnexion</button></a>
        </div>

        <div class="card">
            <h3>⚙️ Contrôle Système SaaS</h3>
            <p>Statut actuel : <b>{{ '🔴 En Maintenance (Bloqué pour les gérants)' if maint else '🟢 Opérationnel' }}</b></p>
            <a href="/admin/toggle-maintenance">
                <button class="{{ 'btn-add' if maint else 'btn-warning' }}" style="width:auto;">
                    {{ 'Désactiver la Maintenance' if maint else 'Basculer en Mode Maintenance' }}
                </button>
            </a>
        </div>

        <div class="card">
            <h3>Liste des Pressings</h3>
            <table>
                <tr style="background:#eee;">
                    <th>Pressing & Contact</th>
                    <th>Statut Demande</th>
                    <th>Fin Pass Urgence</th>
                    <th>Actions Administrateur</th>
                </tr>
                {% for p in pressings %}
                <tr style="{{ 'background-color: #fef2f2;' if p.pass_demande == 1 else '' }}">
                    <td>
                        <b>{{ p.nom_pressing }}</b><br>
                        <small>Gérant : {{ p.nom_gerant }}</small><br>
                        <small>📞 {{ p.telephone }}</small>
                    </td>
                    <td>
                        {% if p.pass_demande == 1 %}
                            <span class="badge" style="background:#dc2626; color:white; padding:6px; font-size:0.85rem;">
                                🚨 PAIEMENT A CONFIRMER
                            </span>
                        {% else %}
                            <span style="color:#666;">Aucune demande</span>
                        {% endif %}
                    </td>
                    <td><small>{{ p.pass_urgence_until or 'Aucun' }}</small></td>
                    <td>
                        {% if p.pass_demande == 1 %}
                            <a href="/admin/valider-pass/{{ p.id }}">
                                <button style="background:#16a34a; color:white; padding:8px; font-size:0.85rem; font-weight:bold; margin-bottom:5px;">
                                    ✅ DÉBLOQUER 2 HEURES
                                </button>
                            </a>
                        {% endif %}
                        <a href="/admin/prolonger/{{ p.id }}"><button style="padding:4px 8px; font-size:0.75rem;">+30 Jours</button></a>
                        <a href="/admin/bloquer/{{ p.id }}"><button class="btn-danger" style="padding:4px 8px; font-size:0.75rem;">Bloquer</button></a>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
    """
    return render_template_string(
        HTML_HEADER + content + HTML_FOOTER, pressings=pressings, maint=maint
    )


@app.route("/admin/valider-pass/<int:pressing_id>")
@admin_required
def admin_valider_pass(pressing_id):
    db = get_db()
    fin_pass = (datetime.now() + timedelta(hours=2)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    db.execute(
        "UPDATE pressings SET pass_urgence_until = ?, pass_demande = 0 WHERE id = ?",
        (fin_pass, pressing_id),
    )
    db.commit()

    flash("⚡ Pass Accès Urgence (2 heures) accordé avec succès au gérant !")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/toggle-maintenance")
@admin_required
def admin_toggle_maintenance():
    db = get_db()
    actuel = check_maintenance()
    nouvel_etat = "0" if actuel else "1"
    db.execute(
        "UPDATE config SET valeur = ? WHERE cle = 'maintenance'",
        (nouvel_etat,),
    )
    db.commit()
    flash(
        "Mode Maintenance désactivé."
        if actuel
        else "Mode Maintenance activé !"
    )
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/prolonger/<int:pressing_id>")
@admin_required
def admin_prolonger(pressing_id):
    db = get_db()
    p = db.execute(
        "SELECT sub_expires_at FROM pressings WHERE id = ?", (pressing_id,)
    ).fetchone()
    if p:
        actuelle = datetime.strptime(
            p["sub_expires_at"], "%Y-%m-%d %H:%M:%S"
        )
        base = max(datetime.now(), actuelle)
        nouvelle = (base + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        db.execute(
            "UPDATE pressings SET sub_expires_at = ? WHERE id = ?",
            (nouvelle, pressing_id),
        )
        db.commit()
        flash("Abonnement prolongé de 30 jours.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bloquer/<int:pressing_id>")
@admin_required
def admin_bloquer(pressing_id):
    db = get_db()
    date_passee = (datetime.now() - timedelta(days=1)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    db.execute(
        "UPDATE pressings SET sub_expires_at = ? WHERE id = ?",
        (date_passee, pressing_id),
    )
    db.commit()
    flash("Accès du pressing bloqué.")
    return redirect(url_for("admin_dashboard"))


# --- AUTHENTIFICATION GÉRANT ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nom_pressing = request.form["nom_pressing"]
        nom_gerant = request.form["nom_gerant"]
        telephone = request.form["telephone"]
        password = generate_password_hash(request.form["password"])
        sub_expires_at = (datetime.now() + timedelta(days=3)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        db = get_db()
        try:
            db.execute(
                "INSERT INTO pressings (nom_pressing, nom_gerant, telephone, password, sub_expires_at) VALUES (?, ?, ?, ?, ?)",
                (
                    nom_pressing,
                    nom_gerant,
                    telephone,
                    password,
                    sub_expires_at,
                ),
            )
            db.commit()
            flash("Compte créé ! 3 jours d'essai offerts.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Ce numéro existe déjà.")

    content = """
        <div class="card">
            <h2>Inscription Gérant (Essai 3 jours)</h2>
            <form method="POST">
                <input type="text" name="nom_pressing" required placeholder="Nom du Pressing">
                <input type="text" name="nom_gerant" required placeholder="Nom du Gérant">
                <input type="text" name="telephone" required placeholder="N° Téléphone">
                <input type="password" name="password" required placeholder="Mot de passe">
                <button type="submit">Démarrer l'essai gratuit</button>
            </form>
            <p><a href="/login">Déjà inscrit ? Connectez-vous</a></p>
        </div>
    """
    return render_template_string(HTML_HEADER + content + HTML_FOOTER)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        telephone = request.form["telephone"]
        password = request.form["password"]

        db = get_db()
        pressing = db.execute(
            "SELECT * FROM pressings WHERE telephone = ?", (telephone,)
        ).fetchone()

        if pressing and check_password_hash(pressing["password"], password):
            session.clear()
            session["pressing_id"] = pressing["id"]
            session["nom_pressing"] = pressing["nom_pressing"]
            return redirect(url_for("dashboard"))
        flash("Identifiants incorrects.")

    content = """
        <div class="card">
            <h2>Connexion Gérant</h2>
            <form method="POST">
                <input type="text" name="telephone" required placeholder="Téléphone">
                <input type="password" name="password" required placeholder="Mot de passe">
                <button type="submit">Se connecter</button>
            </form>
            <p><a href="/register">Créer un compte pressing</a></p>
            <hr>
            <p style="text-align:center;"><small><a href="/admin/login">Espace Super-Admin</a></small></p>
        </div>
    """
    return render_template_string(HTML_HEADER + content + HTML_FOOTER)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/abonnement-expire")
def abonnement_expire():
    content = f"""
        <div class="card" style="text-align: center;">
            <h2 style="color: #dc3545;">⚠️ Essai ou Abonnement expiré</h2>
            <p>Veuillez renouveler votre abonnement mensuel (5 000 FCFA / mois).</p>
            <div class="payment-box">
                <p>Envoyer 5 000 FCFA via Wave / Orange Money au :</p>
                <h3 style="color:#0056b3; margin: 5px 0;">{ADMIN_PHONE}</h3>
            </div>
            <a href="/payer-wave"><button class="btn-add">Activer l'abonnement 30 jours</button></a>
            <br><br><a href="/logout">Se déconnecter</a>
        </div>
    """
    return render_template_string(HTML_HEADER + content + HTML_FOOTER)


@app.route("/payer-wave")
def payer_wave():
    if not session.get("pressing_id"):
        return redirect(url_for("login"))

    db = get_db()
    p = db.execute(
        "SELECT sub_expires_at FROM pressings WHERE id = ?",
        (session["pressing_id"],),
    ).fetchone()
    actuelle = datetime.now()
    if p:
        dt_exp = datetime.strptime(p["sub_expires_at"], "%Y-%m-%d %H:%M:%S")
        if dt_exp > actuelle:
            actuelle = dt_exp

    nouvelle_date = (actuelle + timedelta(days=30)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    db.execute(
        "UPDATE pressings SET sub_expires_at = ? WHERE id = ?",
        (nouvelle_date, session["pressing_id"]),
    )
    db.commit()
    flash("Abonnement mensuel prolongé de 30 jours !")
    return redirect(url_for("dashboard"))


# --- DASHBOARD PRINCIPAL ---
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    commandes = db.execute(
        """
        SELECT c.*, cl.nom as client_nom, cl.telephone as client_tel
        FROM commandes c
        JOIN clients cl ON c.client_id = cl.id
        WHERE c.pressing_id = ?
        ORDER BY c.id DESC
    """,
        (session["pressing_id"],),
    ).fetchall()

    content = """
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <h2>{{ session.get('nom_pressing') }}</h2>
            <a href="/logout"><button class="btn-danger" style="width:auto; padding:8px 15px;">Déconnexion</button></a>
        </div>
        
        <div class="card">
            <a href="/nouvelle-commande"><button>+ Nouveau Dépôt (Lot de vêtements)</button></a>
        </div>

        <div class="card">
            <h3>Liste des Tickets & Dépôts</h3>
            <table>
                <tr>
                    <th>Ticket</th>
                    <th>Client</th>
                    <th>Total</th>
                    <th>Paiement</th>
                    <th>Actions</th>
                </tr>
                {% for c in commandes %}
                <tr>
                    <td><b>{{ c.code_ticket }}</b></td>
                    <td>{{ c.client_nom }}<br><small>{{ c.client_tel }}</small></td>
                    <td><b>{{ c.montant_total }} FCFA</b></td>
                    <td>
                        {% if c.statut_paiement == 'Payé' %}
                            <span class="badge badge-success">Payé ({{ c.mode_paiement }})</span>
                        {% else %}
                            <span class="badge badge-warning">Non Payé</span>
                        {% endif %}
                    </td>
                    <td>
                        <a href="/commande/{{ c.id }}"><button style="padding:6px; font-size:0.8rem; margin-bottom:4px;">Détails / Retrait</button></a>
                        <a href="/recu/{{ c.id }}"><button class="btn-secondary" style="padding:6px; font-size:0.8rem;">📄 Reçu</button></a>
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
    """
    return render_template_string(
        HTML_HEADER + content + HTML_FOOTER, commandes=commandes
    )


# --- NOUVELLE COMMANDE ---
@app.route("/nouvelle-commande", methods=["GET", "POST"])
@login_required
def nouvelle_commande():
    if request.method == "POST":
        nom_client = request.form["client_nom"]
        tel_client = request.form["client_tel"]

        designations = request.form.getlist("designation[]")
        emplacements = request.form.getlist("emplacement[]")
        etats = request.form.getlist("etat[]")
        prix_list = request.form.getlist("prix[]")
        photos = request.files.getlist("photo[]")

        db = get_db()

        client = db.execute(
            "SELECT id FROM clients WHERE telephone = ? AND pressing_id = ?",
            (tel_client, session["pressing_id"]),
        ).fetchone()
        if not client:
            cursor = db.execute(
                "INSERT INTO clients (pressing_id, nom, telephone) VALUES (?, ?, ?)",
                (session["pressing_id"], nom_client, tel_client),
            )
            client_id = cursor.lastrowid
        else:
            client_id = client["id"]

        total_commande = sum([float(p or 0) for p in prix_list])
        code_ticket = f"TICK-{int(datetime.now().timestamp())}"
        cursor = db.execute(
            "INSERT INTO commandes (pressing_id, client_id, code_ticket, montant_total) VALUES (?, ?, ?, ?)",
            (session["pressing_id"], client_id, code_ticket, total_commande),
        )
        commande_id = cursor.lastrowid

        for i in range(len(designations)):
            filename = None
            if i < len(photos) and photos[i] and allowed_file(photos[i].filename):
                fname = secure_filename(photos[i].filename)
                filename = f"{commande_id}_{i}_{int(datetime.now().timestamp())}_{fname}"
                photos[i].save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

            db.execute(
                """
                INSERT INTO articles (commande_id, designation, emplacement_rayon, etat_initial, prix, photo)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    commande_id,
                    designations[i],
                    emplacements[i],
                    etats[i],
                    float(prix_list[i] or 0),
                    filename,
                ),
            )

        db.commit()
        flash("Dépôt multi-vêtements enregistré avec succès !")
        return redirect(url_for("dashboard"))

    content = """
        <div class="card">
            <h2>Nouveau Dépôt Multi-Vêtements</h2>
            <form method="POST" enctype="multipart/form-data">
                <h4>1. Information Client</h4>
                <input type="text" name="client_nom" required placeholder="Nom & Prénom du client">
                <input type="text" name="client_tel" required placeholder="N° Téléphone WhatsApp">
                
                <h4>2. Vêtements déposés</h4>
                <div id="articlesContainer">
                    <div class="item-box">
                        <label><b>Vêtement 1 :</b></label>
                        <input type="text" name="designation[]" required placeholder="Ex: Chemise Blanche Soie">
                        <input type="text" name="emplacement[]" required placeholder="Emplacement : Ex: Rayon A - Cintre 05">
                        <input type="text" name="etat[]" placeholder="État / Remarques (Ex: Tache col droit)">
                        <input type="number" name="prix[]" required placeholder="Prix (FCFA)">
                        <label>📷 Photo du vêtement :</label>
                        <input type="file" name="photo[]" accept="image/*" capture="camera">
                    </div>
                </div>

                <button type="button" class="btn-add" onclick="ajouterVetement()">+ Ajouter un autre vêtement</button>
                <button type="submit">Valider le lot et générer le ticket</button>
            </form>
        </div>

        <script>
            let vetementCount = 1;
            function ajouterVetement() {
                vetementCount++;
                const container = document.getElementById('articlesContainer');
                const div = document.createElement('div');
                div.className = 'item-box';
                div.innerHTML = `
                    <label><b>Vêtement ${vetementCount} :</b></label>
                    <input type="text" name="designation[]" required placeholder="Ex: Pantalon Costume Noir">
                    <input type="text" name="emplacement[]" required placeholder="Emplacement : Ex: Rayon B - Cintre 12">
                    <input type="text" name="etat[]" placeholder="État / Remarques (Ex: Bouton manquant)">
                    <input type="number" name="prix[]" required placeholder="Prix (FCFA)">
                    <label>📷 Photo du vêtement :</label>
                    <input type="file" name="photo[]" accept="image/*" capture="camera">
                    <button type="button" class="btn-danger" onclick="this.parentElement.remove()" style="padding:5px; margin-top:5px;">Supprimer ce vêtement</button>
                `;
                container.appendChild(div);
            }
        </script>
    """
    return render_template_string(HTML_HEADER + content + HTML_FOOTER)


# --- DÉTAILS ET RETRAIT ---
@app.route("/commande/<int:commande_id>", methods=["GET", "POST"])
@login_required
def details_commande(commande_id):
    db = get_db()

    if request.method == "POST":
        mode_p = request.form["mode_paiement"]
        db.execute(
            """
            UPDATE commandes 
            SET statut_paiement = 'Payé', mode_paiement = ?, statut_livraison = 'Livré / Retiré'
            WHERE id = ? AND pressing_id = ?
        """,
            (mode_p, commande_id, session["pressing_id"]),
        )
        db.commit()
        flash("Paiement enregistré et vêtements marqués comme retirés !")
        return redirect(url_for("recu_commande", commande_id=commande_id))

    commande = db.execute(
        """
        SELECT c.*, cl.nom as client_nom, cl.telephone as client_tel
        FROM commandes c
        JOIN clients cl ON c.client_id = cl.id
        WHERE c.id = ? AND c.pressing_id = ?
    """,
        (commande_id, session["pressing_id"]),
    ).fetchone()

    if not commande:
        flash("Commande introuvable.")
        return redirect(url_for("dashboard"))

    articles = db.execute(
        "SELECT * FROM articles WHERE commande_id = ?", (commande_id,)
    ).fetchall()

    content = """
        <div class="card">
            <h2>Ticket : {{ commande.code_ticket }}</h2>
            <p><b>Client :</b> {{ commande.client_nom }} ({{ commande.client_tel }})</p>
            <p><b>Montant Total :</b> {{ commande.montant_total }} FCFA</p>
            <p><b>Paiement :</b> {{ commande.statut_paiement }} {% if commande.statut_paiement == 'Payé' %}({{ commande.mode_paiement }}){% endif %}</p>
            <a href="/"><button class="btn-secondary" style="width:auto; padding:8px 15px;">&larr; Retour</button></a>
            <a href="/recu/{{ commande.id }}"><button class="btn-add" style="width:auto; padding:8px 15px;">📄 Voir / Imprimer le Reçu</button></a>
        </div>

        {% if commande.statut_paiement != 'Payé' %}
        <div class="card" style="border: 2px solid #28a745;">
            <h3>💳 Encaissement & Retrait du Client</h3>
            <form method="POST">
                <label>Sélectionnez le moyen de paiement reçu :</label>
                <select name="mode_paiement" required>
                    <option value="Wave">Wave Mobile Money</option>
                    <option value="Orange Money">Orange Money</option>
                    <option value="MTN MoMo">MTN Mobile Money</option>
                    <option value="Moov Money">Moov Money</option>
                    <option value="Espèces">Espèces (Comptant)</option>
                </select>
                <button type="submit">Valider le paiement et marquer comme Retiré</button>
            </form>
        </div>
        {% endif %}

        <div class="card">
            <h3>Détail des vêtements ({{ articles|length }})</h3>
            <table>
                <tr>
                    <th>Photo</th>
                    <th>Vêtement</th>
                    <th>Emplacement</th>
                    <th>Remarques</th>
                    <th>Prix</th>
                </tr>
                {% for a in articles %}
                <tr>
                    <td>
                        {% if a.photo %}
                            <a href="/uploads/{{ a.photo }}" target="_blank">
                                <img src="/uploads/{{ a.photo }}" class="img-thumb" alt="Photo vêtement">
                            </a>
                        {% else %}
                            <small>Pas de photo</small>
                        {% endif %}
                    </td>
                    <td><b>{{ a.designation }}</b></td>
                    <td><span style="color:#0056b3; font-weight:bold;">📍 {{ a.emplacement_rayon }}</span></td>
                    <td>{{ a.etat_initial or 'R.A.S' }}</td>
                    <td>{{ a.prix }} FCFA</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    """
    return render_template_string(
        HTML_HEADER + content + HTML_FOOTER,
        commande=commande,
        articles=articles,
    )


# --- REÇU DU CLIENT ---
@app.route("/recu/<int:commande_id>")
@login_required
def recu_commande(commande_id):
    db = get_db()
    commande = db.execute(
        """
        SELECT c.*, cl.nom as client_nom, cl.telephone as client_tel, p.nom_pressing, p.telephone as pressing_tel
        FROM commandes c
        JOIN clients cl ON c.client_id = cl.id
        JOIN pressings p ON c.pressing_id = p.id
        WHERE c.id = ? AND c.pressing_id = ?
    """,
        (commande_id, session["pressing_id"]),
    ).fetchone()

    if not commande:
        flash("Commande introuvable.")
        return redirect(url_for("dashboard"))

    articles = db.execute(
        "SELECT * FROM articles WHERE commande_id = ?", (commande_id,)
    ).fetchall()

    wa_msg = f"Bonjour {commande['client_nom']}, voici votre reçu pour votre dépôt chez {commande['nom_pressing']} (Ticket: {commande['code_ticket']}). Montant total : {commande['montant_total']} FCFA. Statut : {commande['statut_paiement']}."
    wa_url = f"https://wa.me/{commande['client_tel']}?text={urllib.parse.quote(wa_msg)}"

    content = """
        <div class="card" style="max-width: 500px; margin: 0 auto; border: 1px solid #ddd;">
            <div style="text-align: center; border-bottom: 2px dashed #ccc; padding-bottom: 10px; margin-bottom: 15px;">
                <h2 style="margin: 5px 0;">{{ commande.nom_pressing }}</h2>
                <p style="margin: 0;"><small>Tél : {{ commande.pressing_tel }}</small></p>
                <h3 style="margin: 10px 0 0 0;">REÇU / FACTURE</h3>
                <p style="margin: 0;"><small>Ticket : <b>{{ commande.code_ticket }}</b> | Date : {{ commande.created_at }}</small></p>
            </div>

            <p><b>Client :</b> {{ commande.client_nom }} ({{ commande.client_tel }})</p>

            <table>
                <tr>
                    <th>Article</th>
                    <th>Remarque</th>
                    <th style="text-align: right;">Prix</th>
                </tr>
                {% for a in articles %}
                <tr>
                    <td>{{ a.designation }}</td>
                    <td><small>{{ a.etat_initial or '-' }}</small></td>
                    <td style="text-align: right;">{{ a.prix }} FCFA</td>
                </tr>
                {% endfor %}
            </table>

            <div style="text-align: right; margin-top: 15px; font-size: 1.1rem;">
                <p><b>TOTAL : {{ commande.montant_total }} FCFA</b></p>
                <p>Statut : <b>{{ commande.statut_paiement }}</b> {% if commande.statut_paiement == 'Payé' %}({{ commande.mode_paiement }}){% endif %}</p>
            </div>

            <div style="text-align: center; margin-top: 20px; font-size: 0.8rem; color: #666;">
                <p>Merci pour votre confiance ! À bientôt.</p>
            </div>
        </div>

        <div style="max-width: 500px; margin: 15px auto; display: flex; gap: 10px;">
            <button onclick="window.print()" class="btn-add">🖨️ Imprimer / PDF</button>
            <a href="{{ wa_url }}" target="_blank" style="width: 100%;"><button style="background: #25D366;">📱 Envoyer par WhatsApp</button></a>
        </div>
        <div style="max-width: 500px; margin: 0 auto;">
            <a href="/"><button class="btn-secondary">&larr; Retour au Tableau de bord</button></a>
        </div>
    """
    return render_template_string(
        HTML_HEADER + content + HTML_FOOTER,
        commande=commande,
        articles=articles,
        wa_url=wa_url,
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

