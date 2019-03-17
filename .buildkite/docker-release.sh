#!/usr/bin/env bash
set -euo pipefail

DOCKER_REPO="lstoll/ssh-bastion-server"

echo "--> Building container"
docker build -t "ssh-bastion-server:${BUILDKITE_COMMIT}" .

if [ "$BUILDKITE_BRANCH" == "master" ]; then
    echo "--> On master, pushing container as latest"
    docker tag "ssh-bastion-server:${BUILDKITE_COMMIT}" "${DOCKER_REPO}:latest"
    docker push "${DOCKER_REPO}:latest"
else
    echo "--> On branch, pushing container as ${BUILDKITE_BRANCH}"
    docker tag "ssh-bastion-server:${BUILDKITE_COMMIT}" "${DOCKER_REPO}:${BUILDKITE_BRANCH}"
    docker push "${DOCKER_REPO}:${BUILDKITE_BRANCH}"
fi

if [ -n "${BUILDKITE_TAG:-}" ]; then
    echo "--> Tagged commit, pushing container as ${BUILDKITE_TAG}"
    docker tag "ssh-bastion-server:${BUILDKITE_COMMIT}" "${DOCKER_REPO}:${BUILDKITE_TAG}"
    docker push "${DOCKER_REPO}:${BUILDKITE_TAG}"
fi
