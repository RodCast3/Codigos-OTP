import functions_framework
from flask import request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
import base64
import os

# Inicializar Firebase solo una vez
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()  # Usa las credenciales predeterminadas (Cloud Function ya las tiene)
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Función auxiliar: genera secreto base32
def generar_secreto_base32():
    return base64.b32encode(os.urandom(10)).decode('utf-8')

# Lógica para agregar secreto al usuario
def agregar_usuario(user_id):
    doc_ref = db.collection('usuarios').document(user_id)
    doc = doc_ref.get()

    if not doc.exists:
        return jsonify({"status": "error", "mensaje": "Usuario no existe"}), 404

    secreto = generar_secreto_base32()
    doc_ref.set({'TOTP': secreto}, merge=True)

    return jsonify({
        "status": "ok",
        "mensaje": f"Usuario '{user_id}' actualizado con secreto TOTP."
    }), 200

# Cloud Function expuesta
@functions_framework.http
def crear_otp_usuario(request):
    try:
        data = request.get_json(silent=True)
        if not data or 'user_id' not in data:
            return jsonify({"status": "error", "mensaje": "ID de usuario no proporcionado"}), 400

        user_id = data['user_id']
        return agregar_usuario(user_id)

    except Exception as e:
        return jsonify({"status": "error", "mensaje": str(e)}), 500
