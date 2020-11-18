#!/bin/bash

docker run -d -p 8080:8080 \
  -e KEYCLOAK_USER=admin \
  -e KEYCLOAK_PASSWORD=admin-password \
  -e PROXY_ADDRESS_FORWARDING=true \
  keycloak:11.0.3
