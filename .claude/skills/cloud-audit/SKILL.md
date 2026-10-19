---
name: cloud-audit
description: Auditoría de seguridad en la nube y contenedores (AWS, Azure, GCP, Kubernetes, Docker, IaC) — IAM y escaladas, almacenamiento expuesto, red, secretos, logging y hardening. Usar para evaluar cuentas cloud y clusters autorizados.
---

# Skill: Auditoría Cloud y Contenedores (0ctopus)

Guía para evaluar entornos en la nube. **Solo cuentas/clusters autorizados**; usar credenciales de solo lectura cuando sea posible.

## Pilares

- **IAM / Identidad**: permisos excesivos, rutas de escalada, roles asumibles, keys de larga vida, separación de deberes.
- **Almacenamiento**: buckets/blobs públicos (S3/GCS/Azure Blob), ACLs, cifrado, versionado.
- **Red**: Security Groups/NSG/firewall, exposición pública, peering, endpoints privados.
- **Logging/Monitoreo**: CloudTrail/Activity Log/Audit Logs, alertas, retención.
- **Secretos**: en variables de entorno, metadata, IaC, imágenes.
- **Contenedores**: imágenes vulnerables, Dockerfile inseguro, privilegios, docker.sock, escapes.
- **Kubernetes**: RBAC, Pod Security, Network Policies, secretos, API server/kubelet.
- **IaC**: malas configuraciones antes del despliegue (Terraform/CloudFormation).

## Herramientas

Prowler · ScoutSuite · PMapper · cloudsplaining · kube-bench · kube-hunter · trivy · checkov/tfsec/kics · s3scanner · cloud_enum · CLIs oficiales (aws/az/gcloud/kubectl).

## Flujo

1. Inventario de assets y cuentas en alcance.
2. Snapshot de configuración (ScoutSuite/Prowler) para una visión amplia.
3. Profundizar por pilar: IAM → almacenamiento → red → logging.
4. Contenedores/K8s: escanear imágenes y configuración del cluster.
5. IaC: escanear el código para prevenir regresiones.

## Severidad (ejemplos)

- Bucket con datos sensibles público / credenciales expuestas → **Crítica**.
- Ruta de escalada a admin de la cuenta → **Crítica/Alta**.
- Servicio administrativo expuesto a Internet → **Alta**.
- Contenedor privilegiado / docker.sock montado → **Alta**.
- Logging deshabilitado → **Media**.

Documentá con evidencia (ARN/recurso, política) y pasá los hallazgos al `report-writer` (skill `reporting`).
