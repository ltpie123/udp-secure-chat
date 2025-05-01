import socket
import threading
import base64
import logging
from udpsecurechat.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class ChatServer:
    def __init__(self, host="0.0.0.0", port=12345):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Dict to store client symmetric keys: {client_addr: aes_key}
        self.clients = {}
        # Dict to store client public keys: {client_addr: rsa_public_key}
        self.client_keys = {}
        # Dict to store client usernames: {client_addr: username}
        self.client_usernames = {}
        self.lock = (
            threading.Lock()
        )  # For thread-safe operations on shared dictionaries

    def start(self):
        """Start the chat server"""
        self.sock.bind((self.host, self.port))
        logger.info(f"Server started on {self.host}:{self.port}")

        # Start message handling
        self.handle_messages()

    def handle_messages(self):
        """Main loop to handle incoming messages"""
        while True:
            try:
                data, addr = self.sock.recvfrom(
                    8192
                )  # Increased buffer size for larger messages
                threading.Thread(target=self.process_message, args=(data, addr)).start()
            except Exception as e:
                logger.error(f"Error receiving message: {e}")

    def process_message(self, data, addr):
        """Process an incoming message from a client"""
        # Check if this is a new client or existing client
        with self.lock:
            is_new_client = addr not in self.clients

        if is_new_client:
            # First message should be the client's public key
            logger.info(f"New connection from {addr}")
            try:
                # Decode the message (assuming base64 encoded public key)
                rsa_pub_key = base64.b64decode(data)

                # Generate AES key for this client
                aes_key = generate_aes_key()

                # Encrypt AES key with client's public key
                encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)

                # Store client information
                with self.lock:
                    self.clients[addr] = aes_key
                    self.client_keys[addr] = rsa_pub_key
                    self.client_usernames[addr] = f"User-{addr[1]}"

                # Send encrypted AES key back to client
                self.sock.sendto(base64.b64encode(encrypted_key), addr)

                # Log client joining
                client_username = self.client_usernames[addr]
                logger.info(f"{client_username} has joined the chat")

                # Send system message to other clients about new user
                join_message = f"SERVER: {client_username} has joined the chat"
                self.broadcast_system_message(join_message, addr)

                logger.info(f"Key exchange completed with {addr}")

            except Exception as e:
                logger.error(f"Error during key exchange with {addr}: {e}")
        else:
            # Regular chat message from existing client
            try:
                # Get client's AES key
                with self.lock:
                    sender_aes_key = self.clients.get(addr)
                    sender_username = self.client_usernames.get(
                        addr, f"Unknown-{addr[1]}"
                    )

                if not sender_aes_key:
                    logger.error(f"No AES key found for client {addr}")
                    return

                # Process the message - it should be a base64 encoded string
                try:
                    # The data is already decoded as bytes, just convert to string
                    message_str = data.decode("utf-8")

                    # Decrypt the message
                    decrypted_message = decrypt_with_aes(sender_aes_key, message_str)
                    logger.info(
                        f"Received message from {sender_username}: {decrypted_message}"
                    )

                    # Broadcast to all other clients
                    self.broadcast_message(decrypted_message, addr)

                except Exception as e:
                    logger.error(f"Error processing message content from {addr}: {e}")
                    logger.error(
                        f"Message data: {data[:100]}"
                    )  # Log first 100 chars for debugging

            except Exception as e:
                logger.error(f"Error processing message from {addr}: {e}")

    def broadcast_message(self, message, sender_addr):
        """Broadcast a message to all clients except the sender"""
        with self.lock:
            for client_addr, aes_key in list(self.clients.items()):
                if client_addr != sender_addr:
                    try:
                        # Encrypt the message with recipient's AES key
                        encrypted_message = encrypt_with_aes(aes_key, message)

                        # Send to the client
                        self.sock.sendto(encrypted_message.encode("utf-8"), client_addr)
                    except Exception as e:
                        logger.error(f"Error sending to {client_addr}: {e}")

    def broadcast_system_message(self, message, exclude_addr=None):
        """Broadcast a system message to all clients"""
        with self.lock:
            for client_addr, aes_key in list(self.clients.items()):
                if client_addr == exclude_addr:
                    continue

                try:
                    # Encrypt the message with recipient's AES key
                    encrypted_message = encrypt_with_aes(aes_key, message)

                    # Send to the client
                    self.sock.sendto(encrypted_message.encode("utf-8"), client_addr)
                except Exception as e:
                    logger.error(f"Error sending system message to {client_addr}: {e}")


if __name__ == "__main__":
    server = ChatServer()
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
