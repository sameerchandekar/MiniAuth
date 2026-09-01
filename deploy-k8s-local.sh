#!/bin/bash

set -e

REGISTRY="ocir.ap-mumbai-1.oci.oraclecloud.com/bmnhzxm9xanv/miniauth"
TAG="v1"

echo "========================================"
echo "1. Building Docker images"
echo "========================================"

docker compose build --no-cache

echo ""
echo "========================================"
echo "2. Tagging images"
echo "========================================"

docker tag miniauth-authorization-server:latest \
  "${REGISTRY}/authorization-server:${TAG}"

docker tag miniauth-user-service:latest \
  "${REGISTRY}/user-service:${TAG}"

docker tag miniauth-resource-server:latest \
  "${REGISTRY}/resource-server:${TAG}"

docker tag miniauth-client-service:latest \
  "${REGISTRY}/client-service:${TAG}"

echo ""
echo "========================================"
echo "3. Verifying tags"
echo "========================================"

docker images | grep "ocir.ap-mumbai-1.oci.oraclecloud.com/bmnhzxm9xanv/miniauth"

echo ""
echo "========================================"
echo "4. Pushing images to OCIR"
echo "========================================"

docker push "${REGISTRY}/authorization-server:${TAG}"
docker push "${REGISTRY}/user-service:${TAG}"
docker push "${REGISTRY}/resource-server:${TAG}"
docker push "${REGISTRY}/client-service:${TAG}"

echo ""
echo "========================================"
echo "Done - all images pushed"
echo "========================================"
