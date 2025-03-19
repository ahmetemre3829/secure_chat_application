# Secure Chat Application
This project includes a server and client application that enables secure messaging. The application uses AES and RSA encryption algorithms to ensure that messages are encrypted and transmitted securely. Communication between the server and client is facilitated through a graphical user interface (GUI) developed using PyQt5.

# Features
* Secure Communication: Messages are encrypted using AES and RSA encryption algorithms.
* Real-Time Messaging: Users can chat in real-time.
* User Authentication: A password is required to connect to the server.
* Active User List: Displays a list of users currently connected to the server.
* Graphical User Interface: A user-friendly interface built using PyQt5.
  
# Installation
## Requirements
* Python 3.x
* PyQt5
* pycryptodome
To install the required dependencies, run the following command:
```pip install PyQt5 pycryptodome```
## Running the Server and Client
### 1-) Starting the Server
* Run the ``server.py`` file.
* Enter the server IP address, port number, and password. (Example: 127.0.0.1 - 8000 - password)
### 2-) Starting the Client
* Run the ``client.py`` file.
* Enter the server IP address, port number, username, and password.
* Click the "CONNECT" button to connect to the server.
### Usage
* Sending Messages: Type your message in the input field and click the "Send" button or press "Enter" to send the message.
* Active Users: The list of users currently connected to the server is automatically displayed.
# Exposing the Server to the Internet Using Ngrok
If you want to make your server accessible over the internet, you can use Ngrok. Ngrok creates a secure tunnel to your local server, allowing external users to connect to it.
## Steps to Use Ngrok
### 1-) Download and Install Ngrok
* Visit ngrok.com and sign up for an account.
* Download and install Ngrok on your machine.
### 2-) Start the Server
* Run your server using server.py as described above.
### 3-) Expose the Server Port
* Open a terminal and run the following command to expose the server's port (replace PORT with the port number your server is running on, e.g. 12345)
        ``ngrok tcp PORT``
### 4-) Get the Public URL
* Ngrok will provide a public URL (e.g., tcp://0.tcp.ngrok.io:12345).
* Share this URL with users who want to connect to your server.
## Example:
* If Ngrok provides the following output: ``Forwarding                    tcp://0.tcp.ngrok.io:54321 -> localhost:12345``
* Clients should connect to ``0.tcp.ngrok.io`` on port ``54321``.
### 5-) Connect Clients
* Clients should use the Ngrok-provided URL (e.g., 0.tcp.ngrok.io) and the port number (e.g., 12345) to connect to the server.
# LICENSE
This project is licensed under the MIT License. For more information, see the LICENSE file.
