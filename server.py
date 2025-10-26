# server.py
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

# אופציונלי — טיפ קטן לטיפוס ובדיקות
import sys          # לביצוע exit או הדפסת שגיאות מסוימות

HOST = "0.0.0.0"
PORT = 1555

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
print(f"waiting for clients to connect on {HOST}:{PORT}")

client, address = s.accept()
print("you're connected to:", address)
def verify_signature():
    server_sk=ed25519.Ed25519PrivateKey.generate()
    server_pk_bytes=server_sk.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw) # messege taransfer to bytes

    server_pk_b64 = base64.b64encode(server_pk_bytes).decode()
    client.send(server_pk_b64.encode())

    client_pk_b64 = client.recv(1024).decode()
    client_pk_bytes = base64.b64decode(client_pk_b64.encode())
    
    
    nonce = make_nonce(tx_counter)
    tx_counter += 1

    tx_counter = 0   # מונה לשליחה
    rx_counter = 0   # מונה לקבלה (מצופה מהצד השני, נבדוק סדר/חד-חד-ערכי)

    def make_nonce(counter: int) -> bytes:
        return counter.to_bytes(12, "big")  # 96-bit big-endian



    client_pk = ed25519.Ed25519PublicKey.from_public_bytes(client_pk_bytes)
    sig=client.recv(1024) 
    client_pk.verify(sig, nonce)
    print("✅ החתימה תקפה — הלקוח אותנטי!")


    try:
        client_pk.verify(sig, nonce)
        print("✅ החתימה תקפה — הלקוח אותנטי!")
    except InvalidSignature:
        print("❌ החתימה נכשלה — ייתכן זיוף או תקלה.")


    client_nonce = client.recv(1024)   
    server_sig = server_sk.sign(client_nonce)
    client.send(server_sig)

    return client_pk_bytes, server_pk_bytes

client_pk_bytes, server_pk_bytes = verify_signature()

def messege_exchange():
    server_eph_sk = x25519.X25519PrivateKey.generate()
    server_eph_pk = server_eph_sk.public_key()  
    server_eph_pk_bytes = server_eph_pk.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw)
    
    server_eph_pk_b64 = base64.b64encode(server_eph_pk_bytes).decode()
    client.send(server_eph_pk_b64.encode())

    client_eph_pk_b64 = s.recv(1024).decode()
    client_eph_pk_bytes = base64.b64decode(server_eph_pk_b64.encode())

    client_eph_pk = x25519.X25519PublicKey.from_public_bytes(client_eph_pk_bytes)
    shared_secret = server_eph_sk.exchange(client_eph_pk)

    transcript = b"|v1|" + server_pk_bytes + client_pk_bytes + client_eph_pk_bytes + server_eph_pk_bytes
    salt = hashlib.sha256(transcript).digest()

    hkdf_c2s = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"chat aead key v1 c->s")
    hkdf_s2c = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"chat aead key v1 s->c")

    key_c2s = hkdf_c2s.derive(shared_secret)  # מפתח לכיוון client -> server
    key_s2c = hkdf_s2c.derive(shared_secret)  # מפתח לכיוון server -> client

    SESSION_ID = hashlib.sha256(salt).digest()[:8]  # 8B session ID for logging/debugging

try:
    client.send("you are connected".encode())
except Exception as e:
    print("send welcome failed:", e)

def send_loop():
    while True:
        try:
            message = input("enter message: ")
            if not message:
                continue
            client.send(message.encode())
        except Exception as e:
            print("send error:", e)
            try: client.close()
            except: pass
            break

def recv_loop():
    while True:
        try:
            data = client.recv(1024)
            if not data:
                print("client disconnected")
                try: client.close()
                except: pass
                break
            print(data.decode(errors="replace"))
        except Exception as e:
            print("recv error:", e)
            try: client.close()
            except: pass
            break

# הפעלת השרשורים (daemon כדי לסגור אוטומטית כשהתוכנית מסתיימת)
threading.Thread(target=send_loop, daemon=True).start()
threading.Thread(target=recv_loop, daemon=True).start()

# השאר את התהליך חי
try:
    threading.Event().wait()
except KeyboardInterrupt:
    print("shutting down")
    try: client.close()
    except: pass
    s.close()
