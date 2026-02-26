import os
import io
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, date
from functools import wraps
from urllib.parse import quote_plus
from secrets import token_urlsafe

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_file, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import extract, inspect, text
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

import pandas as pd

# =========================
# CONFIG FLASK Y BASE
# =========================

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///crm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'clave_super_segura_2026')

db = SQLAlchemy(app)

# =========================
# CONFIG SUBIDA DE ARCHIVOS
# =========================

# PDFs de pólizas
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf'}

# Documentos de usuarios (CUIT, matrícula, DNI) – también PDF
UPLOAD_USERS_FOLDER = 'uploads_usuarios'
os.makedirs(UPLOAD_USERS_FOLDER, exist_ok=True)
app.config['UPLOAD_USERS_FOLDER'] = UPLOAD_USERS_FOLDER


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# =========================
# CONFIG CORREO
# =========================
SMTP_SERVER = "mail.lumaseguros.com.ar"
SMTP_PORT = 465  # SSL
SMTP_USER = "altas@lumaseguros.com.ar"
# La contraseña se toma de una variable de entorno en el servidor
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")


def _enviar_mail(destinatario: str, subject: str, body: str):
    """Función base para enviar mails por SMTP_SSL."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = "Grupo Luma <altas@lumaseguros.com.ar>"
    msg["To"] = destinatario

    try:
        print("Conectando a SMTP...")
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.set_debuglevel(1)  # muestra diálogo SMTP en consola
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"Mail enviado correctamente a {destinatario}")
    except Exception as e:
        print("ERROR EN SMTP:", e)


def enviar_mail_alta(usuario):
    """Mail con link de registro para crear usuario y contraseña."""
    if not usuario.email or not usuario.token_registro:
        print("No hay email o token, no se envía alta.")
        return

    link = url_for('registrar_usuario', token=usuario.token_registro, _external=True)

    subject = "Alta de usuario - CRM Grupo Luma"
    body = f"""Hola {usuario.nombre or ''} {usuario.apellido or ''},

Te dieron de alta en el CRM de Grupo Luma Asesores en Seguros.

Para completar tu registro y crear tu usuario y contraseña, hacé clic en el siguiente enlace:

{link}

Si no solicitaste este acceso, simplemente ignorá este mensaje.

Saludos,
Equipo Luma
"""

    _enviar_mail(usuario.email, subject, body)


def generar_password_temporal():
    """Genera una contraseña temporal razonablemente segura."""
    # Queda algo tipo "H7sd8JkLqA"
    return token_urlsafe(8)


def enviar_mail_reset(usuario, nueva_clave):
    """Mail avisando nueva contraseña temporal."""
    if not usuario.email:
        print("Usuario sin email, no se envía reset.")
        return

    subject = "Restablecimiento de contraseña - CRM Grupo Luma"
    body = f"""Hola {usuario.nombre or ''} {usuario.apellido or ''},

Tu contraseña del CRM Grupo Luma fue restablecida por un administrador.

Nueva contraseña temporal: {nueva_clave}

Te recomendamos cambiarla apenas ingreses al sistema.

Saludos,
Equipo Luma
"""

    _enviar_mail(usuario.email, subject, body)


# =========================
# MODELOS
# =========================

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Datos personales
    nombre = db.Column(db.String(100))
    apellido = db.Column(db.String(100))
    dni = db.Column(db.String(20))
    fecha_nacimiento = db.Column(db.Date, nullable=True)

    es_productor = db.Column(db.Boolean, default=False)
    matricula = db.Column(db.String(50))          # N° matrícula productor
    cuit = db.Column(db.String(20))

    # Rol y permisos
    rol = db.Column(db.String(50))                # 'admin', 'supervisor', 'usuario'
    permisos = db.Column(db.String(255))          # ej: "polizas,finanzas,usuarios"

    # Documentos
    archivo_cuit = db.Column(db.String(255))
    archivo_matricula = db.Column(db.String(255))
    archivo_dni_doc = db.Column(db.String(255))

    # Acceso al sistema
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=True)
    password_hash = db.Column(db.String(200), nullable=True)
    es_admin = db.Column(db.Boolean, default=False)
    activo = db.Column(db.Boolean, default=False)           # True cuando puede loguear
    token_registro = db.Column(db.String(100), unique=True) # link de alta (pendiente)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


class Poliza(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # DATOS DEL CLIENTE
    cliente = db.Column(db.String(150), nullable=False)      # nombre y apellido juntos
    dni = db.Column(db.String(20))
    domicilio = db.Column(db.String(200))
    localidad = db.Column(db.String(100))
    provincia = db.Column(db.String(100))
    productor_interno = db.Column(db.String(100))            # a qué productor interno pertenece
    telefono = db.Column(db.String(30))                      # Tel del cliente para WhatsApp
    email = db.Column(db.String(120))
    fecha_nacimiento = db.Column(db.Date, nullable=True)

    # DATOS DE LA PÓLIZA
    compania = db.Column(db.String(100), nullable=False)
    tipo_seguro = db.Column(db.String(50))                   # Riesgos varios / Patrimonial / Personas
    numero_poliza = db.Column(db.String(100), nullable=False)
    fecha_vencimiento = db.Column(db.Date, nullable=False)
    prima = db.Column(db.Float, nullable=False)
    porcentaje_comision = db.Column(db.Float, nullable=False)

    # Estado general de la póliza (ACTIVA, CANCELADA, BAJA, ANULADA)
    situacion = db.Column(db.String(20), nullable=True)

    # ARCHIVO PDF
    archivo_pdf = db.Column(db.String(255))                  # nombre del archivo PDF guardado

    def calcular_comision(self):
        return self.prima * (self.porcentaje_comision / 100)


class MovimientoFinanciero(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fecha = db.Column(db.Date, nullable=False)
    tipo = db.Column(db.String(20), nullable=False)          # 'ingreso' o 'egreso'
    categoria = db.Column(db.String(100), nullable=False)    # p.ej. 'Comisión', 'Alquiler'
    descripcion = db.Column(db.String(255))
    monto = db.Column(db.Float, nullable=False)
    compania = db.Column(db.String(100))
    cliente = db.Column(db.String(100))
    numero_poliza = db.Column(db.String(100))


# ====== NUEVO MODELO SINIESTRO ======

class Siniestro(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    # Datos básicos del siniestro
    fecha_siniestro = db.Column(db.Date, nullable=False)
    fecha_denuncia = db.Column(db.Date, nullable=False, default=date.today)
    tipo = db.Column(db.String(50), nullable=False)          # Choque, Robo, etc.
    estado = db.Column(db.String(30), nullable=False, default="DENUNCIADO")
    descripcion = db.Column(db.Text)

    # Datos del asegurado / póliza
    asegurado = db.Column(db.String(150))
    dni = db.Column(db.String(20))
    telefono = db.Column(db.String(30))
    email = db.Column(db.String(120))
    compania = db.Column(db.String(100))
    numero_poliza = db.Column(db.String(100))

    def __repr__(self):
        return f"<Siniestro {self.id} - {self.estado}>"


# =========================
# CREAR BASE Y ADMIN INICIAL
# =========================

with app.app_context():
    db.create_all()

    # Aseguramos que exista la columna 'situacion' en la tabla poliza
    inspector = inspect(db.engine)
    try:
        cols_poliza = [c['name'] for c in inspector.get_columns('poliza')]
        if 'situacion' not in cols_poliza:
            db.session.execute(text("ALTER TABLE poliza ADD COLUMN situacion VARCHAR(20)"))
            db.session.commit()
            print("Columna 'situacion' agregada a la tabla poliza.")
    except Exception as e:
        print("No se pudo verificar/agregar columna 'situacion' en poliza:", e)

    # Buscamos por email (puede existir ya en la base)
    admin = Usuario.query.filter_by(email="admin@local").first()
    if not admin:
        # No existe -> lo creamos
        admin = Usuario(
            nombre="Administrador",
            apellido="Sistema",
            email="admin@local",
            username="admin",
            rol="admin",
            es_admin=True,
            activo=True,
            token_registro=None
        )
        admin.set_password("1234")
        db.session.add(admin)
        db.session.commit()
        print("ADMIN CREADO → usuario: admin  contraseña: 1234")
    else:
        # Ya existe -> lo actualizamos para asegurarnos que funciona
        admin.nombre = "Administrador"
        admin.apellido = "Sistema"
        admin.username = "admin"
        admin.rol = "admin"
        admin.es_admin = True
        admin.activo = True
        admin.token_registro = None
        admin.set_password("1234")
        db.session.commit()
        print("ADMIN EXISTENTE ACTUALIZADO → usuario: admin  contraseña: 1234")


# =========================
# DECORADORES
# =========================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = Usuario.query.get(session.get("user_id"))
        if not user or not user.es_admin:
            return "Acceso solo para administradores"
        return f(*args, **kwargs)
    return decorated_function


# =========================
# INDEX PÚBLICO
# =========================

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


# =========================
# LOGIN Y REGISTRO
# =========================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email_or_user = request.form["username"]  # puede ser mail o usuario
        password = request.form["password"]

        user = Usuario.query.filter(
            (Usuario.username == email_or_user) | (Usuario.email == email_or_user)
        ).first()

        if not user:
            return "Usuario / mail no encontrado"

        # Distinguimos estados
        if not user.activo:
            if user.token_registro:
                return "Tu usuario aún no está activo. Revisá el mail de alta para completar el registro."
            else:
                return "Tu usuario se encuentra bloqueado. Consultá con un administrador."

        if user.check_password(password):
            session["user_id"] = user.id
            return redirect(url_for("dashboard"))

        return "Contraseña incorrecta"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/registrar/<token>", methods=["GET", "POST"])
def registrar_usuario(token):
    """Pantalla que llega desde el mail: define username y contraseña."""
    usuario = Usuario.query.filter_by(token_registro=token).first()
    if not usuario:
        return "Token inválido o usuario ya registrado."

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        password2 = request.form["password2"]

        if not username or not password:
            return "Usuario y contraseña son obligatorios."

        if password != password2:
            return "Las contraseñas no coinciden."

        # Verificar que no exista ese username en otro usuario
        if Usuario.query.filter(Usuario.username == username, Usuario.id != usuario.id).first():
            return "Ese nombre de usuario ya está en uso."

        usuario.username = username
        usuario.set_password(password)
        usuario.activo = True
        usuario.token_registro = None

        # Si su rol es admin, marcamos es_admin
        usuario.es_admin = (usuario.rol == "admin")

        db.session.commit()
        return redirect(url_for("login"))

    return render_template("registrar.html", usuario=usuario)


# =========================
# DASHBOARD
# =========================

@app.route("/dashboard")
@login_required
def dashboard():
    polizas = Poliza.query.all()
    hoy = datetime.today().date()

    total = len(polizas)
    vigentes = 0
    por_vencer = 0
    vencidas = 0
    total_comisiones = 0

    for p in polizas:
        dias = (p.fecha_vencimiento - hoy).days
        total_comisiones += p.calcular_comision()

        if dias < 0:
            vencidas += 1
        elif dias <= 30:
            por_vencer += 1
        else:
            vigentes += 1

    movimientos = MovimientoFinanciero.query.all()
    total_ingresos = sum(m.monto for m in movimientos if m.tipo == "ingreso")
    total_egresos = sum(m.monto for m in movimientos if m.tipo == "egreso")
    saldo = total_ingresos - total_egresos

    return render_template(
        "dashboard.html",
        total=total,
        vigentes=vigentes,
        por_vencer=por_vencer,
        vencidas=vencidas,
        total_comisiones=round(total_comisiones, 2),
        total_ingresos=round(total_ingresos, 2),
        total_egresos=round(total_egresos, 2),
        saldo=round(saldo, 2)
    )


# =========================
# USUARIOS (SOLO ADMIN)
# =========================

@app.route("/usuarios")
@login_required
@admin_required
def usuarios():
    lista = Usuario.query.order_by(Usuario.apellido, Usuario.nombre).all()
    return render_template("usuarios.html", usuarios=lista)


@app.route("/crear_usuario", methods=["POST"])
@login_required
@admin_required
def crear_usuario():
    # Datos personales
    nombre = request.form.get("nombre") or None
    apellido = request.form.get("apellido") or None
    dni = request.form.get("dni") or None

    fecha_nac_str = request.form.get("fecha_nacimiento")
    fecha_nacimiento = None
    if fecha_nac_str:
        try:
            fecha_nacimiento = datetime.strptime(fecha_nac_str, "%Y-%m-%d").date()
        except ValueError:
            fecha_nacimiento = None

    es_productor = ("es_productor" in request.form)
    matricula = request.form.get("matricula") or None
    cuit = request.form.get("cuit") or None

    rol = request.form.get("rol") or "usuario"
    permisos_list = request.form.getlist("permisos")
    permisos = ",".join(permisos_list) if permisos_list else None

    email = request.form.get("email")
    if not email:
        return "El mail es obligatorio para el alta."

    # token de registro para mail
    token = token_urlsafe(32)

    nuevo = Usuario(
        nombre=nombre,
        apellido=apellido,
        dni=dni,
        fecha_nacimiento=fecha_nacimiento,
        es_productor=es_productor,
        matricula=matricula,
        cuit=cuit,
        rol=rol,
        permisos=permisos,
        email=email,
        activo=False,              # aún no puede entrar
        token_registro=token
    )
    nuevo.es_admin = (rol == "admin")

    db.session.add(nuevo)
    db.session.commit()

    # Manejo de documentos PDF
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

    archivo_cuit = request.files.get("archivo_cuit")
    if archivo_cuit and archivo_cuit.filename and allowed_file(archivo_cuit.filename):
        filename = secure_filename(archivo_cuit.filename)
        nombre_final = f"user{nuevo.id}_cuit_{timestamp}_{filename}"
        archivo_cuit.save(os.path.join(app.config["UPLOAD_USERS_FOLDER"], nombre_final))
        nuevo.archivo_cuit = nombre_final

    archivo_mat = request.files.get("archivo_matricula")
    if archivo_mat and archivo_mat.filename and allowed_file(archivo_mat.filename):
        filename = secure_filename(archivo_mat.filename)
        nombre_final = f"user{nuevo.id}_matricula_{timestamp}_{filename}"
        archivo_mat.save(os.path.join(app.config["UPLOAD_USERS_FOLDER"], nombre_final))
        nuevo.archivo_matricula = nombre_final

    archivo_dni = request.files.get("archivo_dni")
    if archivo_dni and archivo_dni.filename and allowed_file(archivo_dni.filename):
        filename = secure_filename(archivo_dni.filename)
        nombre_final = f"user{nuevo.id}_dni_{timestamp}_{filename}"
        archivo_dni.save(os.path.join(app.config["UPLOAD_USERS_FOLDER"], nombre_final))
        nuevo.archivo_dni_doc = nombre_final

    db.session.commit()

    # Enviar correo de alta
    enviar_mail_alta(nuevo)

    return redirect(url_for("usuarios"))


@app.route("/usuario_doc/<int:id>/<tipo>")
@login_required
@admin_required
def usuario_doc(id, tipo):
    """Descarga/ver documento de usuario (cuit, matricula, dni)."""
    usuario = Usuario.query.get_or_404(id)
    filename = None

    if tipo == "cuit":
        filename = usuario.archivo_cuit
    elif tipo == "matricula":
        filename = usuario.archivo_matricula
    elif tipo == "dni":
        filename = usuario.archivo_dni_doc

    if not filename:
        return "El usuario no tiene este documento cargado."

    return send_from_directory(app.config["UPLOAD_USERS_FOLDER"], filename)


# ====== NUEVAS ACCIONES SOBRE USUARIOS ======

@app.route("/usuarios/reenviar_mail/<int:id>", methods=["POST"])
@login_required
@admin_required
def usuarios_reenviar_mail(id):
    """Reenvía mail de alta. Si ya no tiene token, genera uno nuevo."""
    usuario = Usuario.query.get_or_404(id)

    if not usuario.token_registro:
        usuario.token_registro = token_urlsafe(32)
        usuario.activo = False
        db.session.commit()

    enviar_mail_alta(usuario)
    return redirect(url_for("usuarios"))


@app.route("/usuarios/reset_password/<int:id>", methods=["POST"])
@login_required
@admin_required
def usuarios_reset_password(id):
    """Genera una nueva contraseña temporal y la envía por mail (opción B)."""
    usuario = Usuario.query.get_or_404(id)

    # No permitimos resetear al admin logueado por accidente
    if usuario.id == session.get("user_id") and usuario.email == "admin@local":
        # igual podrías permitirlo, pero por seguridad lo evitamos
        return redirect(url_for("usuarios"))

    nueva_clave = generar_password_temporal()
    usuario.set_password(nueva_clave)
    usuario.activo = True           # por las dudas estaba bloqueado
    usuario.token_registro = None   # ya no necesita link de registro
    db.session.commit()

    enviar_mail_reset(usuario, nueva_clave)
    return redirect(url_for("usuarios"))


@app.route("/usuarios/bloquear/<int:id>", methods=["POST"])
@login_required
@admin_required
def usuarios_bloquear(id):
    """Bloquea / desbloquea un usuario ya registrado."""
    usuario = Usuario.query.get_or_404(id)

    # No bloquearse a uno mismo (admin)
    if usuario.id == session.get("user_id") and usuario.email == "admin@local":
        return redirect(url_for("usuarios"))

    # Si tiene token_registro => está pendiente de registro, mejor no tocar acá
    if usuario.token_registro:
        # lo dejamos igual, solo redirigimos
        return redirect(url_for("usuarios"))

    # Toggle de activo
    usuario.activo = not usuario.activo
    db.session.commit()

    return redirect(url_for("usuarios"))


# =========================
# PÓLIZAS
# =========================

@app.route("/polizas")
@login_required
def ver_polizas():
    polizas = Poliza.query.all()
    hoy = datetime.today().date()
    lista = []

    for p in polizas:
        dias = (p.fecha_vencimiento - hoy).days

        if dias < 0:
            estado = "VENCIDA"
        elif dias <= 30:
            estado = "POR VENCER"
        else:
            estado = "VIGENTE"

        wa_link = None
        if p.telefono:
            mensaje = (
                f"Hola {p.cliente}, tu póliza {p.numero_poliza} con {p.compania} "
                f"vence el {p.fecha_vencimiento}. Contactate con nosotros para renovar."
            )
            wa_link = f"https://wa.me/{p.telefono}?text={quote_plus(mensaje)}"

        situacion = p.situacion or "ACTIVA"

        lista.append({
            "id": p.id,
            "cliente": p.cliente,
            "dni": p.dni,
            "domicilio": p.domicilio,
            "localidad": p.localidad,
            "provincia": p.provincia,
            "productor_interno": p.productor_interno,
            "telefono": p.telefono,
            "email": p.email,
            "fecha_nacimiento": p.fecha_nacimiento,
            "compania": p.compania,
            "tipo_seguro": p.tipo_seguro,
            "numero_poliza": p.numero_poliza,
            "fecha_vencimiento": p.fecha_vencimiento,
            "estado": estado,
            "situacion": situacion,
            "prima": p.prima,
            "porcentaje": p.porcentaje_comision,
            "comision": round(p.calcular_comision(), 2),
            "wa_link": wa_link,
            "archivo_pdf": p.archivo_pdf
        })

    pdfs = [p for p in lista if p["archivo_pdf"]]

    return render_template("polizas.html", polizas=lista, pdfs=pdfs)


@app.route("/agregar", methods=["POST"])
@login_required
def agregar_poliza():
    # Datos del cliente
    cliente_nombre = request.form["nombre"]
    cliente_apellido = request.form["apellido"]
    cliente = f"{cliente_nombre} {cliente_apellido}".strip()

    dni = request.form.get("dni") or None
    domicilio = request.form.get("domicilio") or None
    localidad = request.form.get("localidad") or None
    provincia = request.form.get("provincia") or None
    productor_interno = request.form.get("productor_interno") or None
    telefono = request.form.get("telefono") or None
    email = request.form.get("email") or None

    fecha_nac_str = request.form.get("fecha_nacimiento")
    fecha_nacimiento = None
    if fecha_nac_str:
        try:
            fecha_nacimiento = datetime.strptime(fecha_nac_str, "%Y-%m-%d").date()
        except ValueError:
            fecha_nacimiento = None

    # Datos de la póliza
    compania = request.form["compania"]
    tipo_seguro = request.form.get("tipo_seguro") or None
    numero_poliza = request.form["numero_poliza"]
    fecha_vencimiento = datetime.strptime(
        request.form["fecha_vencimiento"], "%Y-%m-%d"
    ).date()
    prima = float(request.form["prima"])
    porcentaje = float(request.form["porcentaje"])

    nueva = Poliza(
        cliente=cliente,
        dni=dni,
        domicilio=domicilio,
        localidad=localidad,
        provincia=provincia,
        productor_interno=productor_interno,
        telefono=telefono,
        email=email,
        fecha_nacimiento=fecha_nacimiento,
        compania=compania,
        tipo_seguro=tipo_seguro,
        numero_poliza=numero_poliza,
        fecha_vencimiento=fecha_vencimiento,
        prima=prima,
        porcentaje_comision=porcentaje,
        situacion="ACTIVA"
    )

    # Manejo del archivo PDF
    archivo = request.files.get("archivo_pdf")
    if archivo and archivo.filename and allowed_file(archivo.filename):
        filename_seguro = secure_filename(archivo.filename)
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        nombre_final = f"{numero_poliza}_{timestamp}_{filename_seguro}"
        archivo.save(os.path.join(app.config["UPLOAD_FOLDER"], nombre_final))
        nueva.archivo_pdf = nombre_final

    db.session.add(nueva)
    db.session.commit()
    return redirect(url_for("ver_polizas"))


@app.route("/polizas/importar", methods=["POST"])
@login_required
def importar_polizas():
    archivo = request.files.get("archivo_excel")

    # Si no mandaron archivo, volvemos a la pantalla de pólizas
    if not archivo or archivo.filename == "":
        return redirect(url_for("ver_polizas"))

    filename = archivo.filename.lower()
    if not (filename.endswith(".xls") or filename.endswith(".xlsx")):
        return "El archivo debe ser un Excel (.xls o .xlsx)."

    try:
        # Leemos el Excel directamente desde el archivo subido
        df = pd.read_excel(archivo)
    except Exception as e:
        return f"No se pudo leer el archivo Excel: {e}"

    # Normalizamos nombres de columnas para que coincidan con el modelo
    df.columns = [str(c).strip().lower() for c in df.columns]

    required_cols = [
        "nombre", "apellido", "dni", "domicilio", "localidad", "provincia",
        "productor_interno", "telefono", "email", "fecha_nacimiento",
        "compania", "tipo_seguro", "numero_poliza", "fecha_vencimiento",
        "prima", "porcentaje"
    ]

    # Verificamos que estén todas las columnas del modelo
    for col in required_cols:
        if col not in df.columns:
            return f"Falta la columna '{col}' en el Excel."

    registros_creados = 0

    def clean_str(value):
        """Convierte celdas a string limpio o None si está vacío."""
        if pd.isna(value):
            return None
        s = str(value).strip()
        return s or None

    def parse_date(value):
        """Intenta interpretar fecha en varios formatos."""
        if isinstance(value, date):
            return value
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str) and value.strip():
            for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"):
                try:
                    return datetime.strptime(value.strip(), fmt).date()
                except ValueError:
                    continue
        return None

    def parse_float(value, default=0.0):
        """Convierte a float, acepta comas y puntos."""
        if pd.isna(value):
            return default
        try:
            return float(str(value).replace(",", "."))
        except ValueError:
            return default

    hoy = date.today()

    for _, row in df.iterrows():
        # Nombre y apellido (si la fila está vacía, la salteamos)
        nombre = "" if pd.isna(row["nombre"]) else str(row["nombre"]).strip()
        apellido = "" if pd.isna(row["apellido"]) else str(row["apellido"]).strip()

        if not nombre and not apellido:
            continue

        cliente = f"{nombre} {apellido}".strip()

        dni = clean_str(row["dni"])
        domicilio = clean_str(row["domicilio"])
        localidad = clean_str(row["localidad"])
        provincia = clean_str(row["provincia"])
        productor_interno = clean_str(row["productor_interno"])
        telefono = clean_str(row["telefono"])
        email = clean_str(row["email"])

        fecha_nacimiento = parse_date(row["fecha_nacimiento"])
        fecha_vencimiento = parse_date(row["fecha_vencimiento"])

        # Si no viene fecha de vencimiento, ponemos una por defecto (1 año desde hoy)
        if not fecha_vencimiento:
            try:
                fecha_vencimiento = hoy.replace(year=hoy.year + 1)
            except ValueError:
                # por si hay problema con el día (29/02, etc.)
                fecha_vencimiento = hoy

        compania = clean_str(row["compania"])
        tipo_seguro = clean_str(row["tipo_seguro"])
        numero_poliza = clean_str(row["numero_poliza"])

        # Datos críticos: SIN estos no cargamos la póliza
        if not compania or not numero_poliza:
            continue

        prima = parse_float(row["prima"], 0.0)
        porcentaje = parse_float(row["porcentaje"], 0.0)

        nueva = Poliza(
            cliente=cliente,
            dni=dni,
            domicilio=domicilio,
            localidad=localidad,
            provincia=provincia,
            productor_interno=productor_interno,
            telefono=telefono,
            email=email,
            fecha_nacimiento=fecha_nacimiento,
            compania=compania,
            tipo_seguro=tipo_seguro,
            numero_poliza=numero_poliza,
            fecha_vencimiento=fecha_vencimiento,
            prima=prima,
            porcentaje_comision=porcentaje,
            situacion="ACTIVA"
        )

        db.session.add(nueva)
        registros_creados += 1

    db.session.commit()
    print(f"Importación de pólizas completada. Creadas: {registros_creados}")
    return redirect(url_for("ver_polizas"))


@app.route("/poliza_pdf/<int:id>")
@login_required
def poliza_pdf(id):
    poliza = Poliza.query.get_or_404(id)
    if not poliza.archivo_pdf:
        return "Esta póliza no tiene PDF cargado."
    return send_from_directory(app.config["UPLOAD_FOLDER"], poliza.archivo_pdf)


@app.route("/poliza/cambiar_situacion/<int:id>", methods=["POST"])
@login_required
def cambiar_situacion_poliza(id):
    poliza = Poliza.query.get_or_404(id)
    nueva = request.form.get("situacion")

    if nueva in ["ACTIVA", "CANCELADA", "BAJA", "ANULADA"]:
        poliza.situacion = nueva
        db.session.commit()

    return redirect(url_for("ver_polizas"))


# =========================
# REPORTE MENSUAL EN PDF
# =========================

@app.route("/reporte_form")
@login_required
def reporte_form():
    hoy = date.today()
    return render_template("reporte_form.html", anio_actual=hoy.year, mes_actual=hoy.month)


@app.route("/reporte_mensual")
@login_required
def reporte_mensual():
    anio = request.args.get("anio", type=int)
    mes = request.args.get("mes", type=int)

    if not anio or not mes:
        return "Falta indicar año o mes"

    polizas = Poliza.query.filter(
        extract('year', Poliza.fecha_vencimiento) == anio,
        extract('month', Poliza.fecha_vencimiento) == mes
    ).all()

    total_polizas = len(polizas)
    total_prima = 0
    total_comision = 0
    vigentes = 0
    por_vencer = 0
    vencidas = 0
    hoy = date.today()

    for p in polizas:
        total_prima += p.prima
        total_comision += p.calcular_comision()

        dias = (p.fecha_vencimiento - hoy).days
        if dias < 0:
            vencidas += 1
        elif dias <= 30:
            por_vencer += 1
        else:
            vigentes += 1

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, f"Reporte mensual - {mes:02d}/{anio}")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Total pólizas: {total_polizas}")
    c.drawString(50, height - 100, f"Total prima: $ {round(total_prima, 2)}")
    c.drawString(50, height - 120, f"Total comisión: $ {round(total_comision, 2)}")
    c.drawString(50, height - 140, f"Vigentes: {vigentes}  |  Por vencer (≤30 días): {por_vencer}  |  Vencidas: {vencidas}")

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, height - 170, "Detalle de pólizas:")

    y = height - 190
    c.setFont("Helvetica", 10)

    for p in polizas:
        if y < 80:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)

        linea = f"{p.cliente} | {p.compania} | Poliza: {p.numero_poliza} | Vence: {p.fecha_vencimiento} | Prima: $ {p.prima} | Com.: $ {round(p.calcular_comision(), 2)}"
        c.drawString(50, y, linea)
        y -= 15

    c.showPage()
    c.save()
    buffer.seek(0)

    filename = f"reporte_{anio}_{mes:02d}.pdf"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


# =========================
# SINIESTROS
# =========================

@app.route("/siniestros")
@login_required
def siniestros():
    lista = Siniestro.query.order_by(Siniestro.fecha_siniestro.desc()).all()
    return render_template("siniestros.html", siniestros=lista)


@app.route("/siniestros/crear", methods=["POST"])
@login_required
def crear_siniestro():
    fecha_str = request.form.get("fecha_siniestro")
    if fecha_str:
        try:
            fecha_siniestro = datetime.strptime(fecha_str, "%Y-%m-%d").date()
        except ValueError:
            fecha_siniestro = date.today()
    else:
        fecha_siniestro = date.today()

    nuevo = Siniestro(
        fecha_siniestro=fecha_siniestro,
        fecha_denuncia=date.today(),
        tipo=request.form.get("tipo") or "Sin especificar",
        estado=request.form.get("estado") or "DENUNCIADO",
        descripcion=request.form.get("descripcion"),
        asegurado=request.form.get("asegurado"),
        dni=request.form.get("dni"),
        telefono=request.form.get("telefono"),
        email=request.form.get("email"),
        compania=request.form.get("compania"),
        numero_poliza=request.form.get("numero_poliza"),
    )

    db.session.add(nuevo)
    db.session.commit()

    return redirect(url_for("siniestros"))


@app.route("/siniestros/cambiar_estado/<int:id>", methods=["POST"])
@login_required
def cambiar_estado_siniestro(id):
    siniestro = Siniestro.query.get_or_404(id)
    nuevo_estado = request.form.get("estado")
    if nuevo_estado:
        siniestro.estado = nuevo_estado
        db.session.commit()
    return redirect(url_for("siniestros"))


# =========================
# MÓDULO FINANCIERO
# =========================

@app.route("/finanzas")
@login_required
def finanzas():
    hoy = date.today()
    anio = request.args.get("anio", type=int) or hoy.year
    mes = request.args.get("mes", type=int) or hoy.month

    movimientos = MovimientoFinanciero.query.filter(
        extract('year', MovimientoFinanciero.fecha) == anio,
        extract('month', MovimientoFinanciero.fecha) == mes
    ).order_by(MovimientoFinanciero.fecha.desc()).all()

    total_ingresos = sum(m.monto for m in movimientos if m.tipo == "ingreso")
    total_egresos = sum(m.monto for m in movimientos if m.tipo == "egreso")
    saldo = total_ingresos - total_egresos

    return render_template(
        "finanzas.html",
        movimientos=movimientos,
        total_ingresos=round(total_ingresos, 2),
        total_egresos=round(total_egresos, 2),
        saldo=round(saldo, 2),
        anio=anio,
        mes=mes
    )


@app.route("/finanzas_agregar", methods=["POST"])
@login_required
def finanzas_agregar():
    fecha = datetime.strptime(request.form["fecha"], "%Y-%m-%d").date()
    tipo = request.form["tipo"]
    categoria = request.form["categoria"]
    descripcion = request.form.get("descripcion")
    monto = float(request.form["monto"])
    compania = request.form.get("compania") or None
    cliente = request.form.get("cliente") or None
    numero_poliza = request.form.get("numero_poliza") or None

    mov = MovimientoFinanciero(
        fecha=fecha,
        tipo=tipo,
        categoria=categoria,
        descripcion=descripcion,
        monto=monto,
        compania=compania,
        cliente=cliente,
        numero_poliza=numero_poliza
    )

    db.session.add(mov)
    db.session.commit()

    return redirect(url_for("finanzas", anio=fecha.year, mes=fecha.month))


if __name__ == "__main__":
    app.run(debug=True)