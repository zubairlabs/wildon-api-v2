Service deployment manifests for Wildon.

Files:
- `*-service.yaml`: base Deployment + Service resources per service.
- `autoscaling.yaml`: HPA policies for gateway/public/core/auth services.
- `keda-scaledobjects.yaml`: KEDA ScaledObjects for async worker services.
- `pdb.yaml`: PodDisruptionBudget policies for API-tier stability.

Apply order:
1. `kubectl apply -f infra/k3s/namespaces.yaml`
2. `kubectl apply -f infra/k3s/deployments/*.yaml`

Notes:
- `keda-scaledobjects.yaml` requires KEDA CRDs/operator in the cluster.
- Prometheus endpoints and metric names in scaled objects are placeholders and must match your monitoring stack.
