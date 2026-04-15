#!/bin/bash
set -e

# ================================
# ⚙️ CẤU HÌNH
# ================================
DOCKER_USER="hoangphu20"
IMAGE_NAME="$DOCKER_USER/rpi-model"
TAG="latest"
PLATFORMS="linux/amd64,linux/arm64"

# ================================
# 🐳 BUILD & PUSH DOCKER IMAGE
# ================================
echo "🐳 Đang build multi-arch image (amd64 + arm64)..."

if ! docker buildx ls | grep -q "multiarchbuilder"; then
  docker buildx create --name multiarchbuilder --use
  docker buildx inspect --bootstrap
fi

docker buildx build \
  --platform $PLATFORMS \
  -t $IMAGE_NAME:$TAG \
  -f docker/Dockerfile \
  --push .

echo "✅ Multi-arch image đã được push: $IMAGE_NAME:$TAG"
echo "   → linux/amd64  (PC / Server)"
echo "   → linux/arm64  (Raspberry Pi)"

# ================================
# 📋 HƯỚNG DẪN CHẠY TRÊN RASPBERRY PI
# ================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Để chạy trên Raspberry Pi, dùng lệnh sau:"
echo ""
echo "  docker run -d \\"
echo "    --net=host \\"
echo "    --privileged \\"
echo "    -v /path/to/certs:/app/certs \\"
echo "    -e CERT_PATH=/app/certs/Raspberry-MQTT.cert.pem \\"
echo "    -e KEY_PATH=/app/certs/Raspberry-MQTT.private.key \\"
echo "    -e CA_PATH=/app/certs/root-CA.crt \\"
echo "    -e MQTT_ENDPOINT=a2sdt01uorkibr-ats.iot.ap-southeast-2.amazonaws.com \\"
echo "    -e MQTT_CLIENT_ID=raspi-nfstream \\"
echo "    $IMAGE_NAME:$TAG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "🎉 CI/CD hoàn tất!"
echo "🌐 Raspberry Pi sẽ tự cập nhật qua Watchtower trong vòng 5 phút."
