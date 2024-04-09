# Qumulo SMB Lock Manager - Kubernetes Deployment

** These instructions assume your Kubernetes cluster has network access to `hub.docker.com`

## Installation

- Copy both `.yml` files locally
- Edit the `ConfigMap` section of  `deploy-lock-mgr.yml` with your `TOKEN` and `CLUSTER_ADDRESS`
- Apply both `.yml` files with `kubectl apply -f deploy-lock-mgr.yml,redis-deployment.yml`

This configuration does not provide for an `Ingress`, you may optionally configure one to match your needs and your Kubernetes cluster capabilities.