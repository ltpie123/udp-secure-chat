# UDP Secure Chat

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)

A secure chat application that uses UDP for communication with RSA and AES encryption for security.

## Features

- **UDP-based communication**: Lightweight, fast message exchange
- **Hybrid encryption**:
  - RSA for secure key exchange
  - AES for efficient message encryption
- **Multi-client support**: Chat with multiple users simultaneously
- **Simple command-line interface**: Easy to use, no complex setup

## Security Features

- **RSA key generation**: 2048-bit RSA keys for secure initial handshake
- **AES-128 encryption**: Session keys for efficient symmetric encryption
- **Secure key exchange**: Public key cryptography prevents MITM attacks
- **Encrypted messages**: All chat content is encrypted end-to-end

## Installation

### Option 1: Using Hatch (Recommended)

```console
# Clone the repository
git clone https://github.com/ltpie123/udp-secure-chat.git
cd udp-secure-chat/app

# Install with hatch
pip install hatch
hatch env create
```

### Option 2: Using uv

```console
# Clone the repository
git clone https://github.com/ltpie123/udp-secure-chat.git
cd udp-secure-chat/app

# Install with uv
pip install uv
uv venv
uv sync
```

### Option 3: Traditional pip

```console
# Clone the repository
git clone https://github.com/ltpie123/udp-secure-chat.git
cd udp-secure-chat/app

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package
pip install -e .
```

## Usage

### Starting the Server

```console
# Using hatch shell
hatch run run-server
```

By default, the server listens on all interfaces (0.0.0.0) on port 12345.

### Starting a Client

```console
# Using hatch shell
hatch run run-client
```

## How It Works

1. **Key Exchange**:

   - When a client connects, it generates an RSA key pair
   - The client sends its public key to the server
   - The server generates an AES session key for the client
   - The server encrypts the AES key with the client's public key
   - The client decrypts the AES key with its private key

2. **Secure Messaging**:
   - All messages are encrypted with the client's AES key
   - The server decrypts messages, then re-encrypts them for other clients
   - Each client has its own secure channel with the server

## Dependencies

- Python 3.8+
- pycryptodome (for cryptographic operations)

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.
