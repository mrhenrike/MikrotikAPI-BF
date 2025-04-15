#!/bin/bash

# Name: install-python-3.12.sh
# Purpose: Installs Python 3.12.x on Kali Linux without affecting the system's default Python 3.13.x

PYTHON_VERSION="3.12.2"
INSTALL_DIR="/opt/python-${PYTHON_VERSION}"

echo "[*] Installing dependencies..."
sudo apt update && sudo apt install -y \
  build-essential \
  libssl-dev \
  zlib1g-dev \
  libncurses5-dev \
  libncursesw5-dev \
  libreadline-dev \
  libsqlite3-dev \
  libgdbm-dev \
  libdb5.3-dev \
  libbz2-dev \
  libexpat1-dev \
  liblzma-dev \
  tk-dev \
  wget \
  curl \
  git \
  libffi-dev \
  uuid-dev

echo "[*] Downloading Python ${PYTHON_VERSION}..."
cd /tmp
wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz

echo "[*] Extracting archive..."
tar -xf Python-${PYTHON_VERSION}.tgz
cd Python-${PYTHON_VERSION}

echo "[*] Configuring build options..."
./configure --enable-optimizations --prefix=${INSTALL_DIR}

echo "[*] Compiling Python (this may take a while)..."
make -j$(nproc)

echo "[*] Installing Python ${PYTHON_VERSION} to ${INSTALL_DIR}..."
sudo make altinstall

echo "[*] Adding Python to update-alternatives..."
sudo update-alternatives --install /usr/bin/python python ${INSTALL_DIR}/bin/python3.12 1
sudo update-alternatives --install /usr/bin/python3 python3 ${INSTALL_DIR}/bin/python3.12 1
sudo update-alternatives --install /usr/bin/pip pip ${INSTALL_DIR}/bin/pip3.12 1
sudo update-alternatives --install /usr/bin/pip3 pip3 ${INSTALL_DIR}/bin/pip3.12 1

echo "[*] Setting Python 3.12 as the default version..."
sudo update-alternatives --config python
sudo update-alternatives --config python3

echo "[*] Verifying final versions..."
python --version
python3 --version
pip --version
pip3 --version

echo "[✔] Python ${PYTHON_VERSION} installed successfully!"
echo ""