# client.py
import base64
import hashlib
# רשת/שרשורים/כללי
import socket
import threading
import struct       # framing: pack/unpack 4-byte length, nonce packing
import json         # לשלוח/לקבל JSON בהליך handshake (או תוכל להשתמש בפורמט אחר)
import os           # random, קבצים, chmod
from base64 import b64encode, b64decode  # encode/decode מפתחות/חתימות ל־JSON
from cryptography.exceptions import InvalidSignature
# קריפטו — חתימות, החלפת מפתחות, KDF, AEAD
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# שימוש במילות סיסמה בצורה בטוחה (key storage helper)
from getpass import getpass   # (רק אם יש קוד לשמירת/טעינת מפתח מוצפן)
import sys          # לביצוע exit או הדפסת שגיאות מסוימות

HOST = "127.0.0.1"   # שנה לכתובת השרת אם צריך
PORT = 1555

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print("connected to server", (HOST, PORT))

def verify_signature():
    # מקבל מפתח ציבורי חתימתי של השרת (Base64, בלי framing)
    server_pk_b64 = s.recv(4096).decode()
    server_pk_bytes = base64.b64decode(server_pk_b64.encode())
    print("✅ client got server public key")

    # יוצר מפתח חתימה של הלקוח ושולח ציבורי (Base64)
    client_sk = ed25519.Ed25519PrivateKey.generate()
    client_pk_bytes = client_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    client_pk_b64 = base64.b64encode(client_pk_bytes).decode()
    s.send(client_pk_b64.encode())

    # שלב 1: השרת מאתגר את הלקוח — הלקוח חותם ומחזיר
    challenge_from_server = s.recv(4096)                 # FIX: שם ברור
    sig_from_client = client_sk.sign(challenge_from_server)
    s.send(sig_from_client)

    # שלב 2: הלקוח מאתגר את השרת — השרת חותם ומחזיר
    challenge_for_server = os.urandom(32)                # FIX: 32B ולא 12B
    s.send(challenge_for_server)
    sig_from_server = s.recv(4096)

    server_pk = ed25519.Ed25519PublicKey.from_public_bytes(server_pk_bytes)
    try:
        server_pk.verify(sig_from_server, challenge_for_server)
        print("✅ החתימה תקפה — השרת אותנטי!")
    except InvalidSignature:
        print("❌ החתימה של השרת לא תקפה — ייתכן זיוף/MITM.")
        raise SystemExit(1)

    return client_pk_bytes, server_pk_bytes, client_sk  # FIX: נחזיר גם client_sk אם נרצה בהמשך

client_pk_bytes, server_pk_bytes, client_sk = verify_signature()

def message_exchange():
    # ⚠ סדר ה־ECDH חייב להתאים לשרת:
    # השרת קודם שולח את public eph שלו, THEN הלקוח שולח את שלו.
    # לכן כאן קודם נקבל ואז נשלח.

    # מקבל מפתח אפמרלי ציבורי מהשרת (Base64)
    server_eph_pk_b64 = s.recv(4096).decode()            # FIX: קודם recv (מתאים לשרת)
    server_eph_pk_bytes = base64.b64decode(server_eph_pk_b64.encode())

    # יוצר מפתח אפמרלי של הלקוח ושולח את הציבורי (Base64)
    client_eph_sk = x25519.X25519PrivateKey.generate()
    client_eph_pk_bytes = client_eph_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    client_eph_pk_b64 = base64.b64encode(client_eph_pk_bytes).decode()
    s.send(client_eph_pk_b64.encode())                   # FIX: שליחה אחרי שקיבלנו מהשרת

    # מחשב סוד משותף
    server_eph_pk = x25519.X25519PublicKey.from_public_bytes(server_eph_pk_bytes)
    shared_secret = client_eph_sk.exchange(server_eph_pk)

    # ⚠ סדר transcript חייב להיות זהה לשרת:
    # server_pk_bytes + client_pk_bytes + client_eph_pk_bytes + server_eph_pk_bytes
    transcript = (
        b"|v1|" +
        server_pk_bytes +
        client_pk_bytes +
        client_eph_pk_bytes +
        server_eph_pk_bytes
    )                                                    # FIX: סדר זהה לשרת
    salt = hashlib.sha256(transcript).digest()

    # שני מפתחות נפרדים לכיוונים (labels זהים לשרת)
    hkdf_c2s = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                    info=b"chat aead key v1 c->s")
    hkdf_s2c = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                    info=b"chat aead key v1 s->c")

    key_c2s = hkdf_c2s.derive(shared_secret)  # מפתח לכיוון client -> server
    key_s2c = hkdf_s2c.derive(shared_secret)  # מפתח לכיוון server -> client

    # בינתיים לא משתמשים בלולאות ההודעות (plaintext כרגע), אבל נחזיר לעתיד
    return key_c2s, key_s2c, salt

key_c2s, key_s2c, salt = message_exchange()



session_id = hashlib.sha256(salt).digest()[:8]  # 64-bit session ID גלובלי
def build_aad(direction: bytes, counter: int) -> bytes:
    # SESSION_ID חייב להיות גלובלי/מושג מה-handshake
    return b"|v1|" + session_id + direction + counter.to_bytes(8, "big")



# קבלת הודעת welcome (בשרת הנוכחי היא ב־plaintext)
try:
    welcome = s.recv(4096)
    if welcome:
        print(welcome.decode(errors="replace"))
except Exception:
    pass

def send_loop():
    while True:
        try:
            msg = input("enter message: ")
            if not msg:
                continue
            s.send(msg.encode())  # NOTE: בינתיים plaintext
        except Exception as e:
            print("send error:", e)
            try: s.close()
            except: pass
            break

def recv_loop():
    while True:
        try:
            data = s.recv(4096)
            if not data:
                print("server disconnected")
                try: s.close()
                except: pass
                break
            print("server:", data.decode(errors="replace"))
        except Exception as e:
            print("recv error:", e)
            try: s.close()
            except: pass
            break

threading.Thread(target=send_loop, daemon=True).start()
threading.Thread(target=recv_loop, daemon=True).start()

try:
    threading.Event().wait()
except KeyboardInterrupt:
    print("exiting")
    try: s.close()
    except: pass

