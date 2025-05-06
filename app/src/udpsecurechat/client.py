import socket
import threading
import base64
import logging
import sys
from udpsecurechat.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


class ChatClient:
    def __init__(self, server_host="localhost", server_port=12345, username=None):
        self.server_addr = (server_host, server_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.private_key = None
        self.public_key = None
        self.aes_key = None
        self.username = username or f"User-{id(self) % 10000}"
        self.connected = False
        self.receive_thread = None

    def start(self):
        """Start the chat client"""
        logger.info(f"Starting client as {self.username}...")

        # Generate RSA key pair
        logger.info("Generating RSA key pair...")
        self.private_key, self.public_key = generate_rsa_keypair()

        # Start receiver thread
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

        # Send public key to server for key exchange
        logger.info("Sending public key to server...")
        self.sock.sendto(base64.b64encode(self.public_key), self.server_addr)

        # Wait for AES key to be received
        print("Waiting for secure connection to be established...")
        while not self.aes_key:
            # Small wait to prevent CPU spinning
            import time

            time.sleep(0.1)

        self.connected = True
        logger.info("Connected to chat server!")
        print(f"\nWelcome to the secure chat, {self.username}!")
        print("Type your messages and press Enter to send.")
        print("Type 'exit' to quit.\n")

        # Main loop for user input
        self.handle_user_input()

    def receive_messages(self):
        """Thread function to receive messages from the server"""
        while True:
            try:
                data, _ = self.sock.recvfrom(8192)

                # If we haven't received our AES key yet, this should be it
                if self.aes_key is None:
                    try:
                        encrypted_key = base64.b64decode(data)
                        self.aes_key = decrypt_with_rsa(self.private_key, encrypted_key)
                        logger.info("Received and decrypted AES key from server.")
                    except Exception as e:
                        logger.error(f"Error decrypting AES key: {e}")
                        continue
                else:
                    # This is a chat message, decrypt it
                    try:
                        decrypted_message = decrypt_with_aes(
                            self.aes_key, data.decode()
                        )
                        print(f"\r{decrypted_message}")
                        print("> ", end="", flush=True)  # Re-print prompt
                    except Exception as e:
                        logger.error(f"Error decrypting message: {e}")

            except Exception as e:
                if self.connected:
                    logger.error(f"Error receiving data: {e}")
                if not self.connected:
                    break

    def handle_user_input(self):
        """Handle user input in the main thread"""
        while self.connected:
            try:
                message = input("> ")

                if message.lower() == "exit":
                    logger.info("Exiting chat...")
                    self.connected = False
                    break

                if not message:
                    continue

                # Format the message with username
                formatted_message = f"{self.username}: {message}"

                # Encrypt message using AES
                encrypted_message = encrypt_with_aes(self.aes_key, formatted_message)

                # Send the encrypted message
                self.sock.sendto(encrypted_message.encode(), self.server_addr)

            except KeyboardInterrupt:
                logger.info("Interrupted. Exiting...")
                self.connected = False
                break

            except Exception as e:
                logger.error(f"Error sending message: {e}")

    def close(self):
        """Close the socket and clean up"""
        self.connected = False
        if self.sock:
            self.sock.close()
        logger.info("Client closed.")


def main():
    # Get optional command line arguments for server address and username
    server_host = "localhost"
    server_port = 12345
    username = None

    if len(sys.argv) > 1:
        server_host = sys.argv[1]
    if len(sys.argv) > 2:
        server_port = int(sys.argv[2])
    if len(sys.argv) > 3:
        username = sys.argv[3]

    client = ChatClient(server_host, server_port, username)
    try:
        client.start()
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
