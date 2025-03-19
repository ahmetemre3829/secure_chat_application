#ahmetemre3829
import sys
import socket
import threading
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class ConnectWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('Chat - Connect')
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
            
            #rsa public
            server_public_key = RSA.import_key(self.client.recv(1024))
            cipher_rsa = PKCS1_OAEP.new(server_public_key)
            
            encrypted_pass = cipher_rsa.encrypt(self.inputs['password'].text().encode())
            self.client.send(encrypted_pass)
            
            response = self.client.recv(1024).decode()
            if response == "WRONG_PASS":
                raise ConnectionError("Wrong password")
            
            aes_key = get_random_bytes(16)
            iv = get_random_bytes(16)
            encrypted_aes = cipher_rsa.encrypt(aes_key + iv)
            self.client.send(encrypted_aes)
            
            self.client.send(self.inputs['nick'].text().encode())
            
            self.chat_window = ChatWindow(
                self.client,
                self.inputs['nick'].text(),
                aes_key,
                iv
            )
            self.close()
            self.chat_window.show()
            
        except Exception as e:
            QMessageBox.critical(self, "Connection Error", 
                f"Could not connect to the server:\n{str(e)}")

class ChatWindow(QMainWindow):
    def __init__(self, client, nickname, aes_key, iv):
        super().__init__()
        self.client = client
        self.nickname = nickname
        self.aes_key = aes_key
        self.iv = iv
        self.initUI()
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()
        
    def create_cipher(self, iv):
        return AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        
    def initUI(self):
        self.setWindowTitle(f'Chat Room - {self.nickname}')
        self.setFixedSize(600, 500)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
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
        
        layout.addWidget(self.message_area)
        layout.addLayout(input_layout)
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
        
    def append_message(self, message):
        try:
            decoded = message.decode()
        except:
            decoded = message

        if "joined the room" in decoded:
            formatted = f'<span style="color: yellow;">{decoded}</span>'
        elif "left the room" in decoded:
            formatted = f'<span style="color: yellow;">{decoded}</span>'
        elif ':' in decoded:
            sender, msg = decoded.split(":", 1)
            formatted = f'<span style="color: green;">{sender}:</span><span style="color: white;">{msg}</span>'
        else:
            formatted = f'<span style="color: white;">{decoded}</span>'

        self.message_area.append(formatted)
        self.message_area.verticalScrollBar().setValue(self.message_area.verticalScrollBar().maximum())
                
    def send_message(self):
        message = self.input_field.text().strip()
        if message:
            try:
                new_iv = get_random_bytes(16)
                cipher = self.create_cipher(new_iv)
                padded = pad(f"{self.nickname}: {message}".encode(), AES.block_size)
                encrypted = cipher.encrypt(padded)
                
                self.client.send(new_iv + encrypted)
                self.input_field.clear()
                self.append_message(f"{self.nickname}: {message}".encode())
            except Exception as e:
                print(f"Sending error: {str(e)}")
                
    def receive_messages(self):
        while True:
            try:
                data = self.client.recv(1024)
                if data:
                    received_iv = data[:16]
                    encrypted_message = data[16:]
                    cipher = self.create_cipher(received_iv)
                    decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
                    self.append_message(decrypted)
                else:
                    break
            except Exception as e:
                print(f"Receive error: {str(e)}")
                self.client.close()
                break


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ConnectWindow()
    window.show()
    sys.exit(app.exec_())