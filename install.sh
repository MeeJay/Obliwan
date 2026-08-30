#!/bin/sh
# ObliWAN installer — pulls the compose file, generates secrets, starts the stack.
# NOTE: LF line endings required (see .gitattributes).
set -e

REPO="https://raw.githubusercontent.com/MeeJay/Obliwan/main"
INSTALL_DIR="${OBLIWAN_DIR:-./obliwan}"

echo ""
echo "  ╔══════════════════════════════════╗"
echo "  ║       ObliWAN — Installer        ║"
echo "  ╚══════════════════════════════════╝"
echo ""

# Check docker
if ! command -v docker > /dev/null 2>&1; then
  echo "✗ Docker is not installed. Please install Docker first."
  echo "  https://docs.docker.com/get-docker/"
  exit 1
fi

if ! docker compose version > /dev/null 2>&1; then
  echo "✗ Docker Compose v2 is required. Please update Docker."
  exit 1
fi

# Create install directory
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "→ Installing in: $(pwd)"
echo ""

# Download compose + env example
echo "→ Downloading docker-compose.yml..."
curl -fsSL "$REPO/docker-compose.yml" -o docker-compose.yml

if [ ! -f ".env" ]; then
  echo "→ Downloading .env.example..."
  curl -fsSL "$REPO/.env.example" -o .env.example

  # Generate random secrets
  SESSION_SECRET=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 48 2>/dev/null || \
                   openssl rand -hex 24 2>/dev/null || \
                   echo "please-change-this-secret-$(date +%s)")
  DB_PASSWORD=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 24 2>/dev/null || \
                openssl rand -hex 12 2>/dev/null || \
                echo "please-change-this-password")
  # Credential vault key — 32 bytes, hex encoded. Deliberately distinct from
  # SESSION_SECRET so rotating a session secret cannot destroy the vault (R8).
  ENCRYPTION_KEY=$(openssl rand -hex 32 2>/dev/null || \
                   cat /dev/urandom | tr -dc 'a-f0-9' | head -c 64 2>/dev/null || \
                   echo "")
  if [ -z "$ENCRYPTION_KEY" ]; then
    echo "✗ Could not generate OBLIWAN_ENCRYPTION_KEY (no openssl, no /dev/urandom)."
    echo "  Generate one manually and put it in .env before starting:"
    echo "     openssl rand -hex 32"
    exit 1
  fi

  # Generate .env with the secrets pre-filled
  sed \
    -e "s|SESSION_SECRET=change-this-to-a-random-secret|SESSION_SECRET=$SESSION_SECRET|" \
    -e "s|DB_PASSWORD=changeme|DB_PASSWORD=$DB_PASSWORD|" \
    -e "s|OBLIWAN_ENCRYPTION_KEY=change-this-to-64-hex-chars|OBLIWAN_ENCRYPTION_KEY=$ENCRYPTION_KEY|" \
    .env.example > .env

  echo ""
  echo "  ✓ .env created with generated secrets."
  echo ""
  echo "  ┌────────────────────────────────────────────────────────────────┐"
  echo "  │  BACK UP OBLIWAN_ENCRYPTION_KEY NOW, OFF THIS HOST.            │"
  echo "  │  It encrypts every device credential in your fleet. If you     │"
  echo "  │  lose it, every stored credential becomes unrecoverable and    │"
  echo "  │  must be re-entered by hand — with no error message to warn    │"
  echo "  │  you. It is in $(pwd)/.env"
  echo "  └────────────────────────────────────────────────────────────────┘"
  echo ""
  echo "  → Review and adjust settings if needed: $(pwd)/.env"
  echo ""
else
  echo "  → .env already exists, skipping."
fi

# Create custom directory structure
mkdir -p custom/scripts custom/.ssh
chmod 700 custom/.ssh 2>/dev/null || true

echo "→ Starting ObliWAN..."
echo ""
docker compose pull
docker compose up -d

echo ""
echo "  ╔══════════════════════════════════╗"
echo "  ║       ObliWAN is running!        ║"
echo "  ╚══════════════════════════════════╝"
echo ""
echo "  → Open: http://localhost:3004"
echo "  → Default login: admin / admin123"
echo "  → Change the default password after first login!"
echo ""
echo "  Before ObliWAN can reach any device, this host needs a route to the"
echo "  L2TP tunnel subnet where the fleet lives. See the comments at the top"
echo "  of docker-compose.yml."
echo ""
echo "  Useful commands:"
echo "    docker compose -f $(pwd)/docker-compose.yml logs -f"
echo "    docker compose -f $(pwd)/docker-compose.yml down"
echo "    docker compose -f $(pwd)/docker-compose.yml pull && docker compose up -d  # update"
echo ""
