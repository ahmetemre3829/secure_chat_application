#ahmetemre3829 - ver._1.2
import sys
import socket
import threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

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

class ConnectWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Secure Chat App                ahmetemre3829')
        self.setFixedSize(500, 300)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        self.inputs = {
            'ip': QLineEdit(),
            'port': QLineEdit(),
            'nick': QLineEdit(),
            'password': QLineEdit()
        }
        self.inputs['password'].setEchoMode(QLineEdit.Password)
        
        form = QFormLayout()
        form.setSpacing(18)
        for label, widget in [
            ('IP Adress:', self.inputs['ip']),
            ('Port:', self.inputs['port']),
            ('Nick:', self.inputs['nick']),
            ('Password:', self.inputs['password'])
        ]:
            lbl = QLabel(label)
            lbl.setFont(QFont('Courier New', 18))
            widget.setFixedHeight(40)
            widget.setFont(QFont('VERDANA', 14))
            form.addRow(lbl, widget)
        self.inputs['ip'].returnPressed.connect(self.inputs['port'].setFocus)
        self.inputs['port'].returnPressed.connect(self.inputs['nick'].setFocus)
        self.inputs['nick'].returnPressed.connect(self.inputs['password'].setFocus)
        self.inputs['password'].returnPressed.connect(self.connect_server)

        self.btn_connect = QPushButton('CONNECT')
        self.btn_connect.setFixedHeight(45)

        font = QFont("VERDANA", 14)
        self.btn_connect.setFont(font)
        self.btn_connect.clicked.connect(self.connect_server)
        
        layout.addLayout(form)
        layout.addWidget(self.btn_connect)
        
        self.setLayout(layout)
        self.apply_styles()

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background: #2E3440;
                color: #D8DEE9;
            }
            QPushButton {
                background: #5E81AC;
                border: none;
                border-radius: 4px;
                color: #ECEFF4;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #81A1C1;
            }
            QLineEdit {
                background: #3B4252;
                border: 1px solid #4C566A;
                border-radius: 4px;
                padding: 5px;
            }
        """) 
        
    def connect_server(self):
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((
                self.inputs['ip'].text(),
                int(self.inputs['port'].text())
            ))
            
            server_public_key = RSA.import_key(self.client.recv(1024))
            cipher_rsa = PKCS1_OAEP.new(server_public_key)
            
            encrypted_pass = cipher_rsa.encrypt(self.inputs['password'].text().encode())
            self.client.send(encrypted_pass)
            
            response = self.client.recv(1024).decode()
            if response == "WRONG_PASS":
                raise ConnectionError("Wrong password")
            
            aes_key = get_random_bytes(32)
            handshake_nonce = get_random_bytes(12)
            encrypted_aes = cipher_rsa.encrypt(aes_key + handshake_nonce)
            self.client.send(encrypted_aes)
            
            self.client.send(self.inputs['nick'].text().encode())
            
            self.chat_window = ChatWindow(
                self.client,
                self.inputs['nick'].text(),
                aes_key
            )
            self.close()
            self.chat_window.show()
            
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", 
                f"Could not connect to the server:\n{str(e)}")

class ChatWindow(QMainWindow):
    def __init__(self, client, nickname, aes_key):
        super().__init__()
        self.client = client
        self.nickname = nickname
        self.aes_key = aes_key
        self.active_users = []
        self.initUI()
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()
        
    def initUI(self):
        self.setWindowTitle(f'Chat Room - {self.nickname}')
        self.setFixedSize(800, 500)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        
        left_panel = QVBoxLayout()
        left_panel.setSpacing(15)
        
        self.message_area = QTextBrowser()
        self.message_area.setStyleSheet("""
            background: #3B4252;
            border-radius: 5px;
            padding: 12px;
            font-size: 14px;
        """)
        
        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Type your message...")
        self.input_field.setStyleSheet("""
            background: #434C5E;
            color: #ECEFF4;
            border: 1px solid #4C566A;
            border-radius: 4px;
            padding: 10px;
            font-size: 14px;
        """)
        self.input_field.setFixedHeight(45)
        self.input_field.returnPressed.connect(self.send_message)
        
        self.btn_send = QPushButton("Send")
        self.btn_send.setFixedSize(100, 45)
        font = QFont("Arial", 12)
        self.btn_send.setFont(font)
        self.btn_send.clicked.connect(self.send_message)
        
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.btn_send)
        
        left_panel.addWidget(self.message_area)
        left_panel.addLayout(input_layout)
        
        right_panel = QVBoxLayout()
        right_panel.setSpacing(10)
        right_panel.setContentsMargins(10, 10, 10, 10)
        
        users_label = QLabel("Online Users")
        users_label.setAlignment(Qt.AlignCenter)
        users_label.setFont(QFont("Arial", 14, QFont.Bold))
        users_label.setStyleSheet("color: #81A1C1;")
        
        self.users_list = QListWidget()
        self.users_list.setStyleSheet("""
            QListWidget {
                background: #3B4252;
                border: 1px solid #4C566A;
                border-radius: 5px;
                color: #D8DEE9;
                font-size: 14px;
            }
            QListWidget::item {
                padding: 8px;
            }
            QListWidget::item:hover {
                background: #434C5E;
            }
        """)
        self.users_list.setFixedWidth(200)
        
        right_panel.addWidget(users_label)
        right_panel.addWidget(self.users_list)
        
        main_layout.addLayout(left_panel, 75)
        main_layout.addLayout(right_panel, 25)
        self.apply_styles()
        
    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background: #2E3440;
                color: #D8DEE9;
            }
            QPushButton {
                background: #5E81AC;
                color: #ECEFF4;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #81A1C1;
            }
        """)    
    def update_users_list(self, users):
        self.users_list.clear()
        for user in users:
            item = QListWidgetItem(user)
            item.setForeground(QColor("#88C0D0"))
            self.users_list.addItem(item)
            
    def append_message(self, message):
        if isinstance(message, bytes):
            try:
                message = message.decode("utf-8", errors="ignore")
            except Exception:
                message = str(message)
        
        if message.startswith("ACTIVE_USERS:"):
            users = message.split(":", 1)[1].split(",")
            self.update_users_list(users)
            return

        if "joined the room" in message:
            formatted = f'<span style="color: yellow;">{message}</span>'
        elif "left the room" in message:
            formatted = f'<span style="color: yellow;">{message}</span>'
        elif ':' in message:
            sender, msg = message.split(":", 1)
            formatted = f'<span style="color: green;">{sender}:</span><span style="color: white;">{msg}</span>'
        else:
            formatted = f'<span style="color: white;">{message}</span>'

        self.message_area.append(formatted)
        self.message_area.verticalScrollBar().setValue(self.message_area.verticalScrollBar().maximum())
                
    def send_message(self):
        message = self.input_field.text().strip()
        if message:
            try:
                nonce = get_random_bytes(12)
                cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
                plaintext = f"{self.nickname}: {message}"
                ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
                
                send_data(self.client, nonce + tag + ciphertext)
                
                self.input_field.clear()
                self.append_message(plaintext)
            except Exception as e:
                print(f"Sending error: {str(e)}")
                
    def receive_messages(self):
        while True:
            try:
                data = recv_data(self.client)
                if data:
                    try:
                        if len(data) < 28:
                            print(f"Geçersiz mesaj alındı: {data}")
                            continue
                        
                        nonce = data[:12]
                        tag = data[12:28]
                        ciphertext = data[28:]
                
                        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)
                        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                
                        decoded_message = plaintext.decode("utf-8", errors="ignore")
                        self.append_message(decoded_message)
                    except Exception as e:
                        print(f"Receive error: {str(e)} - Raw data: {data}")
                else:
                    break
            except Exception as e:
                self.append_message(f'<span style="color: red;">Receive error: {str(e)}</span>')
                self.client.close()
                break

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConnectWindow()
    window.show()
    sys.exit(app.exec_())
