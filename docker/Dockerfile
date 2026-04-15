# ============================================================
#  BASE IMAGE — RUN ON BOTH x86_64 & ARM64
# ============================================================
FROM python:3.11-slim

# ============================================================
#  WORKDIR
# ============================================================
WORKDIR /app

# ============================================================
#  CÀI CÔNG CỤ + LIBPCAP + GCC (bắt gói tin NFStream)
# ============================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget bzip2 ca-certificates bash curl libpcap-dev gcc cmake libssl-dev supervisor && \
    rm -rf /var/lib/apt/lists/*

# ============================================================
#  CÀI MICROMAMBA — AUTO ARCH DETECT
# ============================================================
SHELL ["/bin/bash", "-c"]

RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH_DL="64"; else ARCH_DL="aarch64"; fi && \
    echo ">>> Using micromamba arch: ${ARCH_DL}" && \
    wget -q -O micromamba.tar.bz2 "https://micro.mamba.pm/api/micromamba/linux-${ARCH_DL}/latest" && \
    tar -xvjf micromamba.tar.bz2 bin/micromamba && \
    mv bin/micromamba /usr/local/bin/micromamba && \
    rm -rf bin micromamba.tar.bz2

# ============================================================
#  MICROMAMBA INIT
# ============================================================
RUN micromamba shell init -s bash -r /opt/conda && \
    echo "auto_activate_base: false" >> ~/.condarc

# ============================================================
#  TẠO MÔI TRƯỜNG appenv (CÓ NFStream)
# ============================================================
RUN micromamba create -p /opt/conda/envs/appenv python=3.11 \
    -c conda-forge --strict-channel-priority -y \
    flask pandas numpy onnxruntime joblib requests && \
    micromamba clean --all --yes
# Cài NFStream và AWS IoT SDK
RUN /opt/conda/envs/appenv/bin/pip install nfstream awsiotsdk

# ============================================================
#  COPY APP CODE + MODEL
# ============================================================
COPY src/                  ./src
COPY artifacts_onnx/       ./models
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# ============================================================
#  ENV PATH
# ============================================================
ENV PATH="/opt/conda/envs/appenv/bin:$PATH"

# ============================================================
#  EXPOSE + HEALTHCHECK
# ============================================================
EXPOSE 5000

HEALTHCHECK --interval=10s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fs http://localhost:5000/health || exit 1

# ============================================================
#  START SUPERVISOR (RUN 2 PROCESSES)
# ============================================================
CMD ["supervisord", "-n"]
