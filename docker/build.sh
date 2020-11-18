#!/bin/bash

docker build --pull --rm -f "Dockerfile" -t keycloak:11.0.3 "."
