# Warden — container image.
#
#   docker compose up -d        (see docker-compose.yml and README → Docker)
#
# One image, three roles chosen by the command: `web` (the console), `scheduler` (the
# background jobs), and the one-off helpers `gam-setup`, `setup-token`, `seed-admin`.

# ── build ─────────────────────────────────────────────────────────────────────
FROM node:26-bookworm-slim AS build
WORKDIR /app
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npx prisma generate \
    && npm run build \
    && npm prune --omit=dev --no-audit --no-fund

# ── runtime ───────────────────────────────────────────────────────────────────
FROM node:26-bookworm-slim
ARG WARDEN_VERSION=dev
LABEL org.opencontainers.image.title="Warden" \
      org.opencontainers.image.description="Phishing incident-response console for Google Workspace school districts" \
      org.opencontainers.image.source="https://github.com/mmeltonpts/Warden" \
      org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0" \
      org.opencontainers.image.version="${WARDEN_VERSION}"

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      openssl ca-certificates curl xz-utils tini util-linux \
    && rm -rf /var/lib/apt/lists/*

# GAM7, installed to /opt/gam7 — binaries only. The project and authorisation are created
# per district by `gam-setup` and live in the warden user's home (a volume).
#
# Pinned and downloaded directly rather than through GAM's install script: that script needs
# Python to read GitHub's release list and calls GitHub's API unauthenticated, which shared CI
# runners regularly exhaust. A pinned version also makes every image reproducible. Bump
# GAM_VERSION to upgrade (releases: github.com/GAM-team/GAM/releases). glibc2.35 is the
# build for this Debian base (glibc 2.36).
ARG GAM_VERSION=7.48.14
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=x86_64 ;; arm64) arch=arm64 ;; *) echo "unsupported arch ${TARGETARCH}"; exit 1 ;; esac; \
    curl -fsSL -o /tmp/gam.tar.xz \
      "https://github.com/GAM-team/GAM/releases/download/v${GAM_VERSION}/gam-${GAM_VERSION}-linux-${arch}-glibc2.35.tar.xz"; \
    tar -xJf /tmp/gam.tar.xz -C /opt; \
    rm /tmp/gam.tar.xz; \
    test -x /opt/gam7/gam

# Optional AI triage. Signs in with a Claude subscription at run time; no key in the image.
RUN npm install -g @anthropic-ai/claude-code --no-audit --no-fund && npm cache clean --force

RUN groupadd --system --gid 10001 warden \
    && useradd --system --uid 10001 --gid warden --home-dir /var/lib/warden --shell /usr/sbin/nologin warden \
    && install -d -o warden -g warden -m 0750 /var/lib/warden /var/lib/warden/joblogs /var/lib/warden/.gam /var/lib/warden/.claude

WORKDIR /app
COPY --from=build --chown=root:root /app /app
RUN chown -R warden:warden /app/.next

# The image says it is a container, so the console shows container commands for host-side
# steps. This is not operator configuration.
ENV NODE_ENV=production \
    WARDEN_RUNTIME=docker \
    HOME=/var/lib/warden \
    NEXT_TELEMETRY_DISABLED=1

COPY docker/entrypoint.sh /usr/local/bin/warden
RUN chmod 0755 /usr/local/bin/warden

VOLUME ["/var/lib/warden"]
EXPOSE 3006
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/warden"]
CMD ["web"]
