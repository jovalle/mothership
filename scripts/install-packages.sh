#!/bin/bash

apt update

# apt upgrade -y

apt install -y \
  ansible \
	btop \
  apache2-utils \
  btop \
  ca-certificates \
  cifs-utils \
  curl \
  dnsutils \
  extrepo \
  fio \
  glances \
  htop \
  iftop \
  intel-gpu-tools \
  iotop \
  jq \
  lm-sensors \
  mediainfo \
  ncdu \
  neofetch \
  net-tools \
  nfs-common \
  open-iscsi \
  psmisc \
  rsync \
  software-properties-common \
  sudo \
  vim

apt autoremove -y
