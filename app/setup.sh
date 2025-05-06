#!/bin/bash

echo "🔧 Setting up UDP Secure Chat environment..."

# Step 1: Check for Hatch
if ! command -v hatch &>/dev/null; then
   echo "🛠 Hatch not found. Installing Hatch via pip..."
   pip install --user hatch
   echo "✅ Hatch installed."
else
   echo "✅ Hatch is already installed."
fi

# Step 2: Navigate to project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Step 3: Create hatch environment
echo "📦 Creating Hatch environment..."
hatch env create

echo ""
echo "✅ Setup complete!"

echo ""
echo "💡 Next steps:"
echo "  1. Enter the environment:"
echo "     hatch shell"
echo "  2. Run the server:"
echo "     hatch run run-server"
echo "  3. Run a client (in another terminal):"
echo "     hatch run run-client"
echo ""
