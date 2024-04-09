# Qumulo SMB Lock Manager - Kubernetes Deployment

** These instructions assume your Kubernetes cluster has network access to `hub.docker.com`

## Installation

- Copy both `.yml` files locally
- Edit the `ConfigMap` `[CLUSTER]` section of  `deploy-lock-mgr.yml` with your `TOKEN` and `CLUSTER_ADDRESS`
- Edit the `ConfigMap` `[WEBUI]` section of `deploy-lock-mgr.yml` with your `USERNAME` and `PASSWORD`
- Apply both `.yml` files with `kubectl apply -f deploy-lock-mgr.yml,redis-deployment.yml`

**Please note that currently only basic authentication for single web UI user is provided**

This configuration does not provide for an `Ingress`, you may optionally configure one to match your needs and your Kubernetes cluster capabilities.