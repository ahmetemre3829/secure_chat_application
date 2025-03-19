#ahmetemre3829
import socket
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import colorama 
from colorama import Fore
colorama.init(autoreset=True)

print(Fore.CYAN + "Welcome to the server setup program. To start a server, please fill in the information below. #ahmetemre3829\n")
class SecureChatServer:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.clients = []
        self.nicknames = {}
        self.aes_keys = {}


        self.rsa_key = RSA.generate(2048)
        self.cipher_rsa = PKCS1_OAEP.new(self.rsa_key)

    def broadcast(self, message, exclude_client=None):
        if isinstance(message, str):
            message = message.encode()
        for client in self.clients:
            if client == exclude_client:
                continue
            try:
                new_iv = get_random_bytes(16)
                rec_aes_key = self.aes_keys[client]
                cipher = AES.new(rec_aes_key, AES.MODE_CBC, iv=new_iv)
                padded = pad(message, AES.block_size)
                encrypted_message = cipher.encrypt(padded)
                client.send(new_iv + encrypted_message)
            except Exception as e:
                print(Fore.RED + f"Sending message error: {str(e)}")
    
    def handle_client(self, client):
        sender_aes_key = self.aes_keys[client]
        nickname = self.nicknames.get(client, "Unknown")
        try:
            while True:
                data = client.recv(1024)
                if not data:
                    break
                recv_iv = data[:16]
                ciphertext = data[16:]
                cipher = AES.new(sender_aes_key, AES.MODE_CBC, iv=recv_iv)
                try:
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
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
                print(Fore.YELLOW + f"{left_nickname} lost connection..")
                self.broadcast(f"{left_nickname} left the room.")
            if client in self.aes_keys:
                del self.aes_keys[client]
            client.close()

    def send_active_users(self, client):
        active_users = ", ".join(self.nicknames.values())
        message = f"Active members: {active_users}"
        if client in self.aes_keys:
            try:
                new_iv = get_random_bytes(16)
                rec_aes_key = self.aes_keys[client]
                cipher = AES.new(rec_aes_key, AES.MODE_CBC, iv=new_iv)
                padded = pad(message.encode(), AES.block_size)
                encrypted_message = cipher.encrypt(padded)
                client.send(new_iv + encrypted_message)
            except Exception as e:
                print(Fore.RED + f"Sending active members error: {str(e)}")

    def start(self):
        print("\n")
        print(Fore.YELLOW + "✓ Server has started")
        print(Fore.GREEN + "Listening on: " + Fore.CYAN + f"{self.host}:{self.port}")
        print(Fore.GREEN + "Password: " + Fore.CYAN + self.password)
        print("")
        while True:
            client, address = self.server.accept()
            print(Fore.YELLOW + f"New connection: {address}")

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
                aes_key = aes_data[:16]
                self.aes_keys[client] = aes_key

                nickname = client.recv(1024).decode()
                self.nicknames[client] = nickname
                self.clients.append(client)

                print(Fore.YELLOW + f"• {nickname} connected")
                self.broadcast(f"{nickname} joined the room.")

                self.send_active_users(client)

                thread = threading.Thread(target=self.handle_client, args=(client,))
                thread.start()

            except Exception as e:
                print(Fore.RED + f"Connection error: {str(e)}")
                client.close()

if __name__ == "__main__":
    host = input(Fore.MAGENTA + "Server IP: " + Fore.WHITE)
    port = int(input(Fore.MAGENTA + "Server Port: "  + Fore.WHITE))
    password = input(Fore.MAGENTA + "Server Password: " + Fore.WHITE)
    server = SecureChatServer(host, port, password)
    server.start()
