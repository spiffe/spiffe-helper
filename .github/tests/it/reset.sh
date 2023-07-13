#!/bin/bash

# use only to clean docker
docker compose stop
docker system prune
docker rmi $(docker images -qa)