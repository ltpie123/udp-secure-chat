import socket
import threading
import base64
import argparse

from udpsecurechat.crypto_utils import (
    generate_rsa_keypair,
    decrypt_with_rsa,
    encrypt_with_aes,
    decrypt_with_aes,
)

aes_key = None  # Will be set after key exchange


def receive_messages(sock: socket.socket, private_key: bytes):
    global aes_key

    while True:
        data, _ = sock.recvfrom(4096)

        if aes_key is None:
            try:
                encrypted_key = base64.b64decode(data)
                aes_key = decrypt_with_rsa(private_key, encrypted_key)
                print("🔐 AES key received and decrypted.")
            except Exception as e:
                print(f"❌ Failed to decrypt AES key: {e}")
        else:
            try:
                decrypted = decrypt_with_aes(aes_key, data.decode())
                print(f"\n📨 {decrypted}")
            except Exception as e:
                print(f"⚠️ Failed to decrypt message: {e}")


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
