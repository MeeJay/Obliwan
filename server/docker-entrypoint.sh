#!/bin/sh
# NOTE: this file MUST keep LF line endings. With CRLF the kernel reads the
# shebang as "/bin/sh\r" and the container dies with an unhelpful
# "no such file or directory". Enforced by .gitattributes.
set -e

# If /custom/.ssh exists, symlink /root/.ssh to it so the SSH transport
# transparently uses the persisted keys and known_hosts across container
# recreates.
#   chmod 700 custom/.ssh && chmod 600 custom/.ssh/id_*
if [ -d "/custom/.ssh" ]; then
  rm -rf /root/.ssh
  ln -sf /custom/.ssh /root/.ssh
fi

# Fail fast on the one mistake that silently destroys the credential vault
# (risk R8): starting production without a dedicated encryption key.
if [ "${NODE_ENV}" = "production" ]; then
  if [ -z "${OBLIWAN_ENCRYPTION_KEY}" ]; then
    echo "[obliwan] WARNING: OBLIWAN_ENCRYPTION_KEY is not set." >&2
    echo "[obliwan]          Device credentials cannot be stored safely." >&2
    echo "[obliwan]          Generate one with: openssl rand -hex 32" >&2
  elif [ "${OBLIWAN_ENCRYPTION_KEY}" = "change-this-to-64-hex-chars" ]; then
    echo "[obliwan] WARNING: OBLIWAN_ENCRYPTION_KEY is still the example value." >&2
  fi
fi

exec "$@"
