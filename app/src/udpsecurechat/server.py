import socket
import threading
import base64
import argparse

from udpsecurechat.crypto_utils import (
    generate_aes_key,
    encrypt_with_rsa,
    decrypt_with_aes,
    encrypt_with_aes,
)

# Store AES keys per client address
clients = {}  # addr -> aes_key


def handle_messages(sock: socket.socket):
    print("📡 Server ready to receive messages.")
    while True:
        data, addr = sock.recvfrom(4096)

        if addr not in clients:
            try:
                # First message is the client's base64-encoded RSA public key
                rsa_pub_key = base64.b64decode(data)
                aes_key = generate_aes_key()

                encrypted_key = encrypt_with_rsa(rsa_pub_key, aes_key)
                sock.sendto(base64.b64encode(encrypted_key), addr)

                clients[addr] = aes_key
                print(f"🔐 Key exchanged with {addr}")
            except Exception as e:
                print(f"❌ Error during key exchange with {addr}: {e}")
        else:
            try:
                aes_key = clients[addr]
                decrypted_message = decrypt_with_aes(aes_key, data.decode())
                print(f"📨 {addr} says: {decrypted_message}")

                for other_addr, other_key in clients.items():
                    if other_addr != addr:
                        re_encrypted = encrypt_with_aes(other_key, decrypted_message)
                        sock.sendto(re_encrypted.encode(), other_addr)

            except Exception as e:
                print(f"⚠️ Failed to handle message from {addr}: {e}")


def main():
    parser = argparse.ArgumentParser(description="UDP Secure Chat Client")
    parser.add_argument(
        "--host", default="localhost", help="Server host (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=12345, help="Server port (default: 12345)"
    )
    args = parser.parse_args()

    server_addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Step 1: Generate and send RSA public key
    private_key, public_key = generate_rsa_keypair()
    sock.sendto(base64.b64encode(public_key), server_addr)

    # Step 2: Start thread to receive messages
    threading.Thread(
        target=receive_messages, args=(sock, private_key), daemon=True
    ).start()

    # Step 3: Loop to send messages
    try:
        while True:
            msg = input("You: ")
            if aes_key:
                encrypted = encrypt_with_aes(aes_key, msg)
                sock.sendto(encrypted.encode(), server_addr)
            else:
                print("⏳ Waiting for AES key exchange to complete...")
    except KeyboardInterrupt:
        print("\n👋 Exiting chat.")


if __name__ == "__main__":
    main()
