import functions_framework
from flask import request, jsonify
import firebase_admin
from firebase_admin import credentials, firestore
import time
import base64
import hmac
import hashlib
import struct
import pytz
from datetime import datetime

# Inicializar Firebase si aún no se ha hecho
if not firebase_admin._apps:
    cred = credentials.ApplicationDefault()
    firebase_admin.initialize_app(cred)

db = firestore.Client()

# Función para validar el TOTP con tolerancia de 1 ventana antes y 1 después
def validar_totp_con_ventana(secreto_base32, otp_recibido, intervalo=30, digitos=6):
    try:
        secreto = base64.b32decode(secreto_base32, casefold=True)
    except Exception as e:
        raise ValueError("Formato inválido")

    tiempo = int(time.time())

    print("Generando OTPs")
    for delta in [-1, 0, 1]:  # Ventana anterior, actual y próxima
        msg = struct.pack(">Q", tiempo + delta)
        hmac_hash = hmac.new(secreto, msg, hashlib.sha1).digest()
        offset = hmac_hash[-1] & 0x0F
        parte = hmac_hash[offset:offset+4]
        numero = struct.unpack(">I", parte)[0] & 0x7fffffff
        otp_generado = str(numero % (10 ** digitos)).zfill(digitos)

        print(f"Ventana {delta}: OTP generada = {otp_generado}")

        if otp_recibido == otp_generado:
            return True
    return False

def obtener_hora_actual():
    zh = pytz.timezone("America/Mexico_City")
    return datetime.now(zh).strftime("%H:%M:%S")

def obtener_fecha_actual():
    zh = pytz.timezone("America/Mexico_City")
    return datetime.now(zh).strftime("%d-%m-%Y")

def crearDia(documento_dia, hora_actual):
    documento_dia.set({
        "entrada": hora_actual,
        "metodo": "QR",
        "salida": "",
        "num_registros": 1,
        "registro_1": hora_actual
    })

def verificarNumeroRegistros(documento_dia, hora_actual):
    datos = documento_dia.get().to_dict()
    num = datos.get("num_registros", 0) + 1
    actualizaciones = {
        f"registro_{num}": hora_actual,
        "num_registros": num
    }
    if num % 2 == 0:
        actualizaciones["salida"] = hora_actual
    documento_dia.update(actualizaciones)

def guardarAcceso(user_id, tipo_registro):
    try:
        doc_usuario = db.collection("usuarios").document(user_id).get()
        historial_id = doc_usuario.to_dict().get("historial_accesos")
        if not historial_id:
            print("'historial' no encontrado")
            return "Historial no encontrado"

        acceso_doc = db.collection("Control_Asistencia").document(historial_id)
        fecha_actual = obtener_fecha_actual()
        hora_actual = obtener_hora_actual()
        documento_dia = acceso_doc.collection("Accesos").document(fecha_actual)

        if not documento_dia.get().exists:
            if tipo_registro == "salida":
                print("No se puede registrar salida sin entrada")
                return "No se puede registrar salida sin entrada"
            else:
                print("Creando nuevo documento de día")
                crearDia(documento_dia, hora_actual)
                return "OK"
        else:
            datos = documento_dia.get().to_dict()
            num = datos.get("num_registros", 0)
            ultimo_registro = "salida" if num % 2 == 0 else "entrada"
    
            if tipo_registro == ultimo_registro:
                print(f"Ya se registró {ultimo_registro} previamente")
                return f"Ya se registró {ultimo_registro} previamente"
    
            verificarNumeroRegistros(documento_dia, hora_actual)
            print("Acceso registrado")
            return "OK"

    except Exception as e:
        print(f"Error en guardarAcceso(): {e}")

@functions_framework.http
def accesototp(request):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON inválido"}), 400

    user_id = data.get("user_id")
    otp_recibido = data.get("otp")
    tipo_registro = data.get("tipo_registro")

    if not user_id or not otp_recibido or not tipo_registro:
        return jsonify({"error": "Faltan campos en JSON"}), 400

    print(f"Buscando user_id: {user_id} con otp: {otp_recibido}")

    doc_ref = db.collection("usuarios").document(user_id)

    try:
        doc = doc_ref.get()
        if not doc.exists:
            return jsonify({"error": "Usuario no encontrado"}), 404

        datos_usuario = doc.to_dict()
        secreto_base32 = datos_usuario.get("TOTP")
        nombre = datos_usuario.get("nombre")
        last_totp = datos_usuario.get("last_totp")

        if not secreto_base32:
            return jsonify({"error": "El usuario no tiene OTP configurada"}), 404
                
        if otp_recibido == last_totp:
            print("OTP ya fue usada")
            return jsonify({"mensaje": "OTP usado previamente"}), 403
        
        if validar_totp_con_ventana(secreto_base32, otp_recibido):
            print("OTP válido dentro de la ventana")
            doc_ref.update({"last_totp": otp_recibido})
            resultado = guardarAcceso(user_id, tipo_registro)
            if resultado !=  "OK":
                print("Acceso no guardado")
                return jsonify({"mensaje": resultado}), 403    
            return jsonify({"mensaje": nombre}), 200
        else:
            print("Acceso denegado: OTP inválido")
            return jsonify({"mensaje": "OTP incorrecto"}), 403

    except Exception as e:
        print(f"Error consultando Firestore: {e}")
        return jsonify({"error": "Error al consultar Firestore"}), 500
