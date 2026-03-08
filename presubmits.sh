#!/bin/bash

# Exit at the first failure.
set -e
# These are the commands run by the prow presubmit job.

mkdir -p ${GOPATH}/src/sigs.k8s.io
ln -s `pwd` ${GOPATH}/src/sigs.k8s.io/node-local-dns

echo "installing sudo"
apt-get update && apt-get install sudo -y

make build
make test
make all-containers
