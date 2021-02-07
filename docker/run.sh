#!/bin/bash

read -s -p "Keycloak admin password: " KEYCLOAK_PASSWORD

echo
echo Starting Keycloak Docker container

docker run -d -p 8080:8080 \
  -e KEYCLOAK_USER=admin \
  -e KEYCLOAK_PASSWORD=${KEYCLOAK_PASSWORD} \
  -e PROXY_ADDRESS_FORWARDING=true \
  keycloak:11.0.3
