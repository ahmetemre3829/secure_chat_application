#ahmetemre3829 - ver._1.3
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import colorama 
from colorama import Fore
import yaml
import sys
import os
from pyngrok import ngrok, conf
from pathlib import Path
import getpass
colorama.init(autoreset=True)

print(Fore.CYAN + "Welcome to the server setup program. To start a server, please enter the requested informations below. #ahmetemre3829 - ver_1.3\n")

def send_data(sock, data):
    length = len(data)
    sock.sendall(length.to_bytes(4, byteorder='big') + data)

def recvall(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def recv_data(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = int.from_bytes(raw_len, byteorder='big')
    return recvall(sock, msg_len)

class SecureChatServer:
    def __init__(self, host, port, password, public_url=None):
        self.host = host
        self.port = port
        self.password = password
        self.public_url = public_url
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.clients = []
        self.nicknames = {}
        self.aes_keys = {}

        self.rsa_key = RSA.generate(4096)
        self.cipher_rsa = PKCS1_OAEP.new(self.rsa_key)

    def broadcast_active_users(self):
        active_users = list(self.nicknames.values())
        message = f"ACTIVE_USERS:{','.join(active_users)}"
        self.broadcast(message)
        
    def broadcast(self, message, exclude_client=None):
        if isinstance(message, str):
            message = message.encode()
        
        for client in self.clients:
            if client == exclude_client:
                continue
            
            try:
                if client not in self.aes_keys:
                    print(Fore.RED + f"Client {client} için AES anahtarı bulunamadı!")
                    continue

                new_nonce = get_random_bytes(12)
                rec_aes_key = self.aes_keys[client]
                cipher = AES.new(rec_aes_key, AES.MODE_GCM, nonce=new_nonce)
                ciphertext, tag = cipher.encrypt_and_digest(message)
                send_data(client, new_nonce + tag + ciphertext)

            except Exception as e:
                print(Fore.RED + f"Mesaj gönderme hatası ({self.nicknames.get(client, 'Bilinmeyen')}): {str(e)}")

    def handle_client(self, client):
        sender_aes_key = self.aes_keys[client]
        nickname = self.nicknames.get(client, "Unknown")
        try:
            while True:
                data = recv_data(client)
                if not data:
                    break
                if len(data) < 28:
                    print(Fore.RED + f": {data}")
                    continue
                recv_nonce = data[:12]
                tag = data[12:28]
                ciphertext = data[28:]
                cipher = AES.new(sender_aes_key, AES.MODE_GCM, nonce=recv_nonce)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception as e:
                    print(Fore.RED + f"Decryption error: {str(e)}")
                    continue
                print(Fore.GREEN + f"Incoming message --> " + Fore.CYAN + f"{plaintext.decode()}")
                self.broadcast(plaintext, exclude_client=client)
        except Exception as e:
            print(Fore.RED + f"Client connection error: {str(e)}")
        finally:
            if client in self.clients:
                self.clients.remove(client)
            if client in self.nicknames:
                left_nickname = self.nicknames[client]
                del self.nicknames[client]
                print(Fore.YELLOW + f"• {left_nickname} lost connection..")
                self.broadcast(f"{left_nickname} left the room.")
                self.broadcast_active_users()
            if client in self.aes_keys:
                del self.aes_keys[client]
            client.close()

    def start(self): 
        print("\n")
        print(Fore.YELLOW + "✓ Server has started")
        print(Fore.GREEN + "• Listening on: " + Fore.CYAN + f"{self.host}:{self.port}")
        if self.public_url:
            print(Fore.GREEN + "• Ngrok: " + Fore.CYAN + f"{str(self.public_url).split('"')[1].replace('tcp://', '')}")

        print(Fore.GREEN + "• Password: " + Fore.CYAN + self.password)
        print("")
        while True:
            client, address = self.server.accept()
            print(Fore.YELLOW + f"• New connection: {address}")

            try:
                client.send(self.rsa_key.publickey().export_key())

                encrypted_password = client.recv(1024)
                password = self.cipher_rsa.decrypt(encrypted_password).decode()
                if password != self.password:
                    client.send("WRONG_PASS".encode())
                    print(Fore.RED + "Wrong password")
                    client.close()
                    continue
                else:
                    client.send("OK".encode())

                encrypted_aes = client.recv(1024)
                aes_data = self.cipher_rsa.decrypt(encrypted_aes)
                if len(aes_data) < 44:
                    print(Fore.RED + "AES key and handshake nonce are not received correctly!")
                    client.close()
                    continue
                aes_key = aes_data[:32]

                self.aes_keys[client] = aes_key

                nickname = client.recv(1024).decode()
                self.nicknames[client] = nickname
                self.clients.append(client)

                print(Fore.YELLOW + f"• {nickname} connected")
                self.broadcast(f"{nickname} joined the room.")
                self.broadcast_active_users()

                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.start()

            except Exception as e:
                print(Fore.RED + f"Connection error: {str(e)}")
                client.close()


def get_token_file_path():
    user = getpass.getuser()
    folder = Path(f"C:/Users/{user}/AppData/Local/ngrok")
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "ngrok.yml"

def read_token():
    path = get_token_file_path()
    if path.exists():
        with open(path, "r") as f:
            data = yaml.safe_load(f)
            if data:
                if "agent" in data and "authtoken" in data["agent"]:
                    return data["agent"]["authtoken"]
                elif "authtoken" in data:
                    return data["authtoken"]
    return None

def save_token(token):
    path = get_token_file_path()
    content = f"""region: us
version: '2'
authtoken: {token}
"""
    with open(path, "w") as f:
        f.write(content)

def get_or_ask_token():
    EXPECTED_TOKEN_LENGTH = 49
    token = read_token()
    if token and len(token) == EXPECTED_TOKEN_LENGTH:
        print(Fore.YELLOW + "Opening tunnel...")
        return token
    else:
        token = input(Fore.MAGENTA + "Enter ngrok authtoken: " + Fore.WHITE).strip()
        if len(token) == EXPECTED_TOKEN_LENGTH:
            save_token(token)
            print(Fore.GREEN + "Authtoken saved")
            return token
        else:
            print(Fore.RED + f"Invalid token length. Expected {EXPECTED_TOKEN_LENGTH} characters.")
            return None


def start_ngrok():
    while True:
        token = get_or_ask_token()
        if not token:
            print(Fore.RED + "Authtoken error.")
            continue

        stdout_fileno = sys.stdout
        stderr_fileno = sys.stderr
        devnull = open(os.devnull, 'w')
        sys.stdout = devnull
        sys.stderr = devnull

        try:
            public_url = ngrok.connect(f"{host}:{port}", "tcp")
        except Exception as e:
            sys.stdout = stdout_fileno
            sys.stderr = stderr_fileno

            error_msg = str(e).lower()
            if "The authtoken you specified is properly formed, but it is invalid." in error_msg:
                print(Fore.RED + "Ngrok error: " + Fore.WHITE + "Invalid authtoken.")
                path = get_token_file_path()
                if path.exists():
                    path.unlink()
                print(Fore.YELLOW + "Please enter a valid authtoken.")
                continue
            else:
                print(Fore.RED + f"Ngrok eror: "+ Fore.WHITE  +f"{e}")
                return None

        sys.stdout = stdout_fileno
        sys.stderr = stderr_fileno

        print(Fore.GREEN + f"Ngrok tunnel opened: "+Fore.WHITE+f"{str(public_url).replace('NgrokTunnel: ', '')}")
        return public_url


if __name__ == "__main__":
    ng = input(Fore.YELLOW + "Do you want to use ngrok? (y/n): " + Fore.WHITE)
    host = input(Fore.MAGENTA + "Server IP: " + Fore.WHITE)
    port = int(input(Fore.MAGENTA + "Server Port: "  + Fore.WHITE))
    password = input(Fore.MAGENTA + "Server Password: " + Fore.WHITE)
    if ng.strip().lower() == 'y':
        public_url=start_ngrok()
    else:
        public_url = None
    server = SecureChatServer(host, port, password, public_url)
    server.start()
