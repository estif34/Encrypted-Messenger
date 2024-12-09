# Encrypted-Messenger
This is a secure messaging application built with Node.js and Socket.IO, implementing the Double Ratchet Algorithm for end-to-end encryption. Users can register with unique usernames, exchange certificates, and securely send messages to one another in real-time.

## Features
- User Registration: Users can register with unique usernames.
- Real-Time Messaging: Messages are sent and received in real-time using Socket.IO.
- End-to-End Encryption: Implements the Double Ratchet Algorithm to ensure message confidentiality.
- Certificate Exchange: Users exchange certificates for secure communication.
- Secure Message Transmission: Messages are encrypted before being sent and decrypted upon receipt.

## Technologies Used
- Backend:
    - Node.js: A JavaScript runtime for the backend.
    - Socket.IO: Real-time, bidirectional communication between clients and servers.
    - Express: Minimalist web framework for Node.js.
    - Cryptographic functions from Node.js crypto module.
- Frontend:
    - HTML, CSS, and JavaScript for a simple user interface.
    - Socket.IO client for real-time communication with the backend.

## Setup and Installation
### Prerequisites
- Node.js installed on your system.
- A code editor (e.g., VS Code).
- A browser for testing the application.

### Steps
1. Clone the Repository
   ```git clone https://github.com/estif34/Encrypted-Messenger.git```
3. Install Dependencies
   ```npm install```
5. Run the Server
   ```node server.js```
7. Run the Frontend
  - Open the index.html file in your preferred code editor.
  - Use a live server extension (e.g., in VS Code) to serve the frontend.

## Usage
1. User Registration:
     - Enter a unique username to register.
     - You’ll receive a confirmation message when registration is successful.
2. User List:
     - The interface displays a list of other online users.
     - Click on a username to exchange certificates and start secure communication.
3. Messaging:
     - Once certificates are exchanged, you can send encrypted messages to the selected user.
  

## Demo
### Bob's side
![image](https://github.com/user-attachments/assets/8a4d8b1e-fe3c-4d5b-8f2d-e9a8488e0a26)
### Alice's side
![image](https://github.com/user-attachments/assets/0fef58d6-76d1-4011-a1aa-772fa4d3d23c)


## Project Structure
```
encrypted-messenger/
├── lib.js           # Cryptographic primitives and Double Ratchet logic
├── messenger.js     # MessengerClient implementation
├── server.js        # Node.js server with Socket.IO logic
├── index.html       # Frontend for user interface
├── styles.css       # Styles for the frontend (if separate)
├── package.json     # Dependencies and project metadata
└── README.md        # Project documentation
```

