# NetWatch Local k3d Runbook

## Purpose and boundary

This runbook provides a **free local Kubernetes-style deployment** for NetWatch using k3d. k3d runs a lightweight k3s cluster in Docker for local development; it is not a hosted environment and it does not provide production HA. The overlay deliberately keeps one NetWatch replica, `Recreate` updates, SQLite persistence, and no `hostNetwork`. Run scans only against networks and assets for which the operator has explicit authorization.

The k3d path is intended for local feature testing, UI review, API smoke tests, and operator training. It is not evidence of Google Cloud/GKE capacity, multi-tenant isolation, PostgreSQL correctness, Redis coordination, disaster recovery, or production SLOs.

## Prerequisites

Install Docker Engine or another Docker-compatible runtime, `kubectl`, and `k3d`. The official k3d documentation lists Docker and kubectl as requirements. Confirm the tools before starting:

```bash
docker version
kubectl version --client
k3d version
```

Docker Desktop licensing depends on the organization and use case. For a large company, use Docker Engine or an approved commercial Docker subscription according to the organization's licensing policy.

## Create the local cluster

From the repository root, create a single-server cluster with a local registry and a port mapping for the optional NodePort service:

```bash
k3d registry create netwatch-registry --port 5111
k3d cluster create netwatch-local \
  --servers 1 \
  --agents 0 \
  --registry-create netwatch-registry:0.0.0.0:5111 \
  --port "8080:30080@loadbalancer"
```

If the registry or cluster already exists, inspect it first rather than deleting it:

```bash
k3d registry list
k3d cluster list
```

## Build and load the image

Build the normal single-tenant image. Do not use `Dockerfile.enterprise` for this local path unless the optional enterprise dependencies are explicitly needed:

```bash
docker build -t netwatch:local -f Dockerfile .
k3d image import netwatch:local -c netwatch-local
```

The k3d overlay uses `imagePullPolicy: IfNotPresent`, so the imported local image is used without a remote registry push.

## Create local secrets

Create a local-only secret. Use a generated value for the audit key and do not commit the resulting file:

```bash
kubectl create namespace netwatch --dry-run=client -o yaml | kubectl apply -f -
kubectl -n netwatch create secret generic netwatch-secrets \
  --from-literal=NETWATCH_AUDIT_HMAC_KEY="$(openssl rand -hex 32)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Role keys and OIDC values are intentionally not supplied by this runbook. Configure them only through a reviewed local secret process if they are needed for the test. The default deployment must not expose credentials in Git, ConfigMaps, image layers, or frontend code.

## Deploy

Apply the local overlay and wait for the one pod to become ready:

```bash
kubectl apply -k deploy/kustomization-k3d.yaml
kubectl -n netwatch rollout status deployment/netwatch --timeout=180s
kubectl -n netwatch get pods,svc,pvc
```

Access the service at `http://127.0.0.1:8080` through the k3d load-balancer mapping. The safer alternative is a temporary port-forward:

```bash
kubectl -n netwatch port-forward service/netwatch 8000:8000
```

Then use `http://127.0.0.1:8000` locally.

## Smoke checks

```bash
curl -fsS http://127.0.0.1:8080/api/health/live
kubectl -n netwatch logs deployment/netwatch --tail=100
kubectl -n netwatch describe pod -l app.kubernetes.io/name=netwatch
```

Run the repository's bounded API benchmark only against this local service, and do not use it to launch broad network scans automatically:

```bash
python3 scripts/benchmark_api.py --base-url http://127.0.0.1:8080
```

## Updating the local deployment

Build a new image, import it, and apply the overlay. Because this is the SQLite single-instance path, updates use `Recreate` rather than active-active rolling replacement:

```bash
docker build -t netwatch:local -f Dockerfile .
k3d image import netwatch:local -c netwatch-local
kubectl apply -k deploy/kustomization-k3d.yaml
kubectl -n netwatch rollout status deployment/netwatch --timeout=180s
```

Before destructive maintenance, create and verify a backup using the documented Admin workflow. Do not delete the PVC as part of an ordinary update.

## Inspect and clean up

```bash
kubectl -n netwatch get all,pvc
kubectl -n netwatch logs deployment/netwatch --follow
k3d cluster delete netwatch-local
k3d registry delete netwatch-registry
```

Deleting the cluster deletes its local workload state. Preserve any backup needed for later verification before cleanup.

## What this local path does not prove

A successful k3d deployment proves only that the image and single-instance Kubernetes manifest can run locally. It does not certify shared-service readiness. PostgreSQL tenant migrations, Redis leases, external workers, off-host backups, failure injection, load evidence, independent security testing, and GKE-specific controls still require their own staging environment and evidence.

## References

[1] [k3d Documentation](https://k3d.io/)

[2] [Docker Desktop License Agreement](https://docs.docker.com/subscription/desktop-license/)
