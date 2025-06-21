# Codigos-OTP – Microservicios para autenticación por códigos temporales

Repositorio que contiene los microservicios de generación y validación de **códigos OTP (One-Time Password)** para el "sistema de control de acceso a áreas restringidas mediante reconocimiento facial y codigos OTP".

Estos servicios están diseñados para usuarios **invitados** que acceden al sistema a través de códigos QR con claves OTP generadas dinámicamente.

---

## 📄 Descripción

Este repositorio implementa dos microservicios basados en **Cloud Functions**:

- `crearOTPUsuario`: genera una clave OTP única y la almacena en el documento correspondiente del usuario anfitrión en Firebase Firestore. El valor generado se utiliza para codificarse como un código QR.
- `accesoOTP`: valida una OTP proporcionada por un usuario invitado, verificando su coincidencia con la almacenada en Firestore, y autoriza o deniega el acceso dependiendo del resultado.

Ambos servicios están expuestos mediante endpoints públicos sobre HTTPS.

---

## 🔐 Seguridad

- Los códigos OTP generados tienen un tiempo de 30 segundos y se pueden usar una sola vez.
- El acceso a Firestore se realiza mediante autenticación con Firebase Admin SDK.
- Las claves generadas no se transmiten en texto plano fuera del entorno seguro.

---

## 🧠 Tecnologías utilizadas

- Python 3.x
- Google Cloud Functions
- Firebase Firestore
- PyOTP (para generación de OTPs basados en tiempo)
- Flask (estructura para testing local)
