#!/bin/bash

set -e

UNIFI_MONGO_HOST="${UNIFI_MONGO_HOST:-127.0.0.1}"
UNIFI_MONGO_PORT="${UNIFI_MONGO_PORT:-27117}"

CONTAINER_NAME="${CONTAINER_NAME:-unifi-mongodb-clone}"
CONTAINER_PORT="${CONTAINER_PORT:-27018}"
MONGO_VERSION="${MONGO_VERSION:-4.4}"

DUMP_DIR="/tmp/unifi-mongodb-dump-$$"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}=== UniFi MongoDB Clone Script ===${NC}"
echo ""


if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed or not in PATH${NC}"
    exit 1
fi
if ! command -v mongodump &> /dev/null; then
    echo -e "${YELLOW}Warning: mongodump not found.${NC}"
    exit 1
fi
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${YELLOW}Stopping and removing existing container: ${CONTAINER_NAME}${NC}"
    docker stop "${CONTAINER_NAME}" 2>/dev/null || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null || true
fi

echo -e "${GREEN}Starting MongoDB ${MONGO_VERSION} container...${NC}"
docker run -d \
    --name "${CONTAINER_NAME}" \
    -p "${CONTAINER_PORT}:27017" \
    mongo:${MONGO_VERSION}

echo -e "${YELLOW}Waiting for MongoDB container to be ready...${NC}"
sleep 5

MAX_RETRIES=30
RETRY_COUNT=0
until docker exec "${CONTAINER_NAME}" mongosh --eval "db.adminCommand('ping')" --quiet > /dev/null 2>&1 || \
      docker exec "${CONTAINER_NAME}" mongo --eval "db.adminCommand('ping')" --quiet > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo -e "${RED}Error: MongoDB container failed to start${NC}"
        docker logs "${CONTAINER_NAME}"
        exit 1
    fi
    echo -n "."
    sleep 1
done
echo ""
echo -e "${GREEN}MongoDB container is ready${NC}"

mkdir -p "${DUMP_DIR}"

echo -e "${GREEN}Dumping all databases from ${UNIFI_MONGO_HOST}:${UNIFI_MONGO_PORT}...${NC}"
mongodump \
    --host="${UNIFI_MONGO_HOST}" \
    --port="${UNIFI_MONGO_PORT}" \
    --out="${DUMP_DIR}"

if [ ! -d "${DUMP_DIR}" ] || [ -z "$(ls -A ${DUMP_DIR})" ]; then
    echo -e "${RED}Error: Database dump failed or no databases found${NC}"
    rm -rf "${DUMP_DIR}"
    exit 1
fi

echo -e "${YELLOW}Databases dumped:${NC}"
ls -1 "${DUMP_DIR}" | while read db; do
    echo "  - $db"
done

echo -e "${GREEN}Copying dump to container...${NC}"
docker cp "${DUMP_DIR}" "${CONTAINER_NAME}:/tmp/mongodump"

echo -e "${GREEN}Restoring all databases to container...${NC}"
docker exec "${CONTAINER_NAME}" mongorestore \
    "/tmp/mongodump" \
    --quiet 2>/dev/null || \
docker exec "${CONTAINER_NAME}" sh -c "mongorestore /tmp/mongodump --quiet"

echo -e "${GREEN}Cleaning up temporary files...${NC}"
rm -rf "${DUMP_DIR}"
docker exec "${CONTAINER_NAME}" rm -rf "/tmp/mongodump"

echo -e "${GREEN}Verifying clone...${NC}"
DB_LIST=$(docker exec "${CONTAINER_NAME}" mongosh --quiet --eval "db.adminCommand('listDatabases').databases.map(d => d.name).join('\n')" 2>/dev/null || \
          docker exec "${CONTAINER_NAME}" mongo --quiet --eval "db.adminCommand('listDatabases').databases.map(function(d) { return d.name; }).join('\n')")

echo ""
echo -e "${GREEN}=== Clone Complete ===${NC}"
echo -e "Container name: ${YELLOW}${CONTAINER_NAME}${NC}"
echo -e "MongoDB port: ${YELLOW}${CONTAINER_PORT}${NC}"
echo ""
echo -e "Databases in container:"
echo "$DB_LIST" | while read db; do
    if [ -n "$db" ] && [ "$db" != "admin" ] && [ "$db" != "config" ] && [ "$db" != "local" ]; then
        echo -e "  ${YELLOW}- $db${NC}"
    fi
done
echo ""
echo "Connect to the cloned MongoDB with:"
echo -e "${YELLOW}  mongosh mongodb://localhost:${CONTAINER_PORT}${NC}"
echo ""
echo "To stop the container:"
echo -e "${YELLOW}  docker stop ${CONTAINER_NAME}${NC}"
echo ""
echo "To remove the container:"
echo -e "${YELLOW}  docker rm ${CONTAINER_NAME}${NC}"
echo ""
