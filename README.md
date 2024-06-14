<div align="center">

<img src="./mothership.jpeg" height="400px"/>

# Mothership

The homelab application motherload.

</div>

## 📖 Overview

Collection of augmentations for the homelab and especially the media server ([watchtower](https://github.com/jovalle/watchtower)).

Running on a VM provisioned by [terraform](https://terraform.io), configured by [ansible](https://ansible.com), and running [docker](https://docker.com) containers.

## 🐳 Docker Compose

At the heart of the project is Docker, Docker Compose v2 to be specific. Makes for easy deployment to, and management of, a singular host.

See `docker-compose.yaml` for the services deployed.
## 📋 Prerequisites

### Environment File

`.env` stores common variables to be referenced by virtually all docker compose services via `env_file` parameter. See sample below.

```sh
# general
DOMAIN="example.net"
DOMAIN_EXT="example.com"
HOST_IP=192.168.1.2
PGID=1000
PUID=1000
TZ="America/New_York"

# apps
LIDARR_API_KEY=REDACTED
OVERSEER_API_KEY=REDACTED
PORTAINER_API_KEY=REDACTED
PROWLARR_API_KEY=REDACTED
RADARR_API_KEY=REDACTED
SONARR_API_KEY=REDACTED
TAUTULLI_API_KEY=REDACTED

# cloudflare
CF_API_EMAIL=REDACTED
CF_API_KEY=REDACTED

# gluetun
OPENVPN_USER=REDACTED
OPENVPN_PASSWORD=REDACTED

# grafana
GRAFANA_USER=REDACTED
GRAFANA_PASSWORD=REDACTED

# qbittorrent
QBITTORRENT_USER=REDACTED
QBITTORRENT_PASSWORD=REDACTED

# media
BOOKS_PATH=/mnt/hulkpool/books
DOWNLOADS_PATH=/mnt/hulkpool/downloads
MISC_PATH=/mnt/hulkpool/misc
MOVIES_PATH=/mnt/hulkpool/movies
MUSIC_PATH=/mnt/hulkpool/music
TVSHOWS_PATH=/mnt/whirlpool/tvshows

# optional (if deploying containers remotely and without systemd)
DOCKER_HOST_IP=${HOST_IP}
DOCKER_HOST="ssh://root@${DOCKER_HOST_IP}"
```

⚠️ Virtually all docker compose services are leveraging `.env`. Changes to the file will trigger recreations of virtually all containers. May look into creating specific environment files for each container to address this. Wish I could just uses SOPS for inline encryption of `docker-compose.yaml`.

## 🚀 Deployment

Ideally, `git clone` this repo at `/etc/mothership` on the target host.

```sh
git clone git@github.com:jovalle/mothership.git /etc/mothership
```

To deploy locally:

```sh
make install
```

To deploy remotely, ensure:

- Host is accessible via SSH
- Host has docker compose installed
- SSH params are tweaked (`MaxStartups 200`)
- `DOCKER_HOST` is set locally

```sh
make start
```
