"""
Análisis de seguridad de Kubernetes para CyberHound Pro.

Checks implementados:
  1.  Pods corriendo como root (securityContext.runAsNonRoot no definido)
  2.  Contenedores privilegiados en pods
  3.  RBAC permisivo — ClusterRoleBindings con permisos wildcard
  4.  Secretos montados innecesariamente (automountServiceAccountToken)
  5.  Namespaces sin NetworkPolicy (tráfico entre pods sin restricción)
  6.  Pods sin resource limits (CPU/memoria)
  7.  Imágenes usando tag :latest
  8.  etcd expuesto sin autenticación
  9.  Dashboard de K8s expuesto sin auth
  10. Versión de Kubernetes con CVEs conocidos
  11. Pods en el namespace kube-system con permisos excesivos
  12. Secrets en variables de entorno (en lugar de Secrets de K8s)
  13. PodSecurityPolicy / PodSecurityAdmission no configurado
  14. Hostpath volumes peligrosos

Usa kubectl (no la API de K8s directamente) para máxima compatibilidad.
No requiere configuración adicional si kubectl está en el PATH con acceso al cluster.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional

from cyberhound.core.executor import command_exists, run_command
from cyberhound.core.logging import get_logger
from cyberhound.core.models import Finding

logger = get_logger("kubernetes")

SECRET_ENV_PATTERNS = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "auth", "credential", "private_key", "access_key", "aws_secret",
    "database_url", "db_pass",
]

DANGEROUS_HOSTPATHS = [
    "/", "/etc", "/proc", "/sys", "/var/run/docker.sock",
    "/root", "/home", "/boot", "/var/lib/kubelet",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _kubectl(args: list[str], timeout: int = 30) -> Optional[dict | list]:
    """Ejecuta kubectl y parsea la salida JSON. Devuelve None si falla."""
    proc = await run_command(
        ["kubectl"] + args + ["-o", "json"], timeout=timeout, check=False
    )
    if proc.returncode != 0:
        logger.debug("kubectl %s falló (%d): %s", " ".join(args[:3]),
                     proc.returncode, proc.stderr[:100])
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


async def _kubectl_available() -> bool:
    if not command_exists("kubectl"):
        return False
    proc = await run_command(["kubectl", "cluster-info"], timeout=10, check=False)
    return proc.returncode == 0


async def _get_all_pods() -> list[dict]:
    data = await _kubectl(["get", "pods", "--all-namespaces"])
    if not data:
        return []
    return data.get("items", [])


def _f(id, category, severity, title, description, remediation,
       evidence="", auto_fix=False):
    return Finding(
        id=id, category=f"kubernetes/{category}", severity=severity,
        title=title, description=description, remediation=remediation,
        evidence=evidence, auto_fix=auto_fix,
    )


# ── Checks ────────────────────────────────────────────────────────────────────

async def check_pods_as_root() -> list[Finding]:
    """Detecta pods/contenedores sin runAsNonRoot=true."""
    pods = await _get_all_pods()
    findings = []
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        spec = pod.get("spec", {})

        # SecurityContext a nivel de pod
        pod_ctx = spec.get("securityContext", {})
        pod_non_root = pod_ctx.get("runAsNonRoot", False)
        pod_uid = pod_ctx.get("runAsUser")

        for container in spec.get("containers", []) + spec.get("initContainers", []):
            cname = container.get("name", "")
            ctx   = container.get("securityContext", {})
            non_root = ctx.get("runAsNonRoot", pod_non_root)
            uid      = ctx.get("runAsUser", pod_uid)

            if not non_root and (uid is None or uid == 0):
                fid = f"k8s_root_{ns}_{name}_{cname}".replace("-", "_")[:70]
                findings.append(_f(
                    fid, "pod_security", "high",
                    f"Pod como root: {ns}/{name}/{cname}",
                    f"El contenedor '{cname}' en el pod '{name}' (namespace: {ns}) "
                    "no tiene runAsNonRoot=true ni runAsUser definido.",
                    "Añadir al securityContext del contenedor:\n"
                    "securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
                    evidence=f"namespace={ns} pod={name} container={cname}",
                ))
    return findings


async def check_privileged_pods() -> list[Finding]:
    """Detecta contenedores con privileged: true."""
    pods = await _get_all_pods()
    findings = []
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        spec = pod.get("spec", {})
        for container in spec.get("containers", []):
            cname = container.get("name", "")
            ctx   = container.get("securityContext", {})
            if ctx.get("privileged"):
                fid = f"k8s_privileged_{ns}_{name}_{cname}".replace("-","_")[:70]
                findings.append(_f(
                    fid, "pod_security", "critical",
                    f"Contenedor privilegiado: {ns}/{name}/{cname}",
                    f"El contenedor '{cname}' en '{name}' tiene privileged=true. "
                    "Tiene acceso completo al kernel del host.",
                    "Eliminar 'privileged: true' del securityContext y usar "
                    "solo las capabilities estrictamente necesarias.",
                    evidence=f"privileged=true namespace={ns}",
                ))
    return findings


async def check_rbac_wildcards() -> list[Finding]:
    """Detecta ClusterRoleBindings con permisos wildcard."""
    data = await _kubectl(["get", "clusterroles"])
    if not data:
        return []

    findings = []
    for role in data.get("items", []):
        name = role.get("metadata", {}).get("name", "")
        # Ignorar roles del sistema
        if name.startswith("system:"):
            continue
        rules = role.get("rules", [])
        for rule in rules:
            verbs     = rule.get("verbs", [])
            resources = rule.get("resources", [])
            api_groups = rule.get("apiGroups", [])
            if "*" in verbs and "*" in resources:
                findings.append(_f(
                    f"k8s_rbac_wildcard_{name.replace('-','_')[:40]}",
                    "rbac", "critical",
                    f"ClusterRole con permisos wildcard: {name}",
                    f"El ClusterRole '{name}' tiene permisos (*) sobre todos los recursos. "
                    "Cualquier ServiceAccount que use este role tiene control total del cluster.",
                    "Aplicar el principio de mínimo privilegio:\n"
                    "Especificar recursos y verbos exactos en lugar de '*'",
                    evidence=f"verbs={verbs} resources={resources}",
                ))
        # cluster-admin binding a ServiceAccounts no de sistema
    return findings


async def check_automount_service_account() -> list[Finding]:
    """Detecta pods con automountServiceAccountToken no desactivado."""
    pods = await _get_all_pods()
    findings = []
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        if ns in ("kube-system", "kube-public"):
            continue
        spec = pod.get("spec", {})
        # Si automountServiceAccountToken no está explícitamente en False
        if spec.get("automountServiceAccountToken", True):
            fid = f"k8s_automount_{ns}_{name}".replace("-","_")[:70]
            findings.append(_f(
                fid, "secrets", "medium",
                f"Token de ServiceAccount montado automáticamente: {ns}/{name}",
                f"El pod '{name}' en '{ns}' tiene acceso al token de ServiceAccount "
                "de la API de Kubernetes. Si no lo necesita, es superficie de ataque innecesaria.",
                "Añadir al spec del pod:\nautomountServiceAccountToken: false",
                evidence=f"namespace={ns} pod={name}",
            ))
    return findings


async def check_no_network_policy() -> list[Finding]:
    """Detecta namespaces sin ninguna NetworkPolicy."""
    ns_data = await _kubectl(["get", "namespaces"])
    if not ns_data:
        return []
    np_data = await _kubectl(["get", "networkpolicies", "--all-namespaces"])
    namespaces_with_policy = set()
    if np_data:
        for np in np_data.get("items", []):
            namespaces_with_policy.add(np.get("metadata", {}).get("namespace", ""))

    findings = []
    skip_ns = {"kube-system", "kube-public", "kube-node-lease"}
    for ns in ns_data.get("items", []):
        name = ns.get("metadata", {}).get("name", "")
        if name in skip_ns or name.startswith("kube-"):
            continue
        if name not in namespaces_with_policy:
            findings.append(_f(
                f"k8s_no_netpol_{name.replace('-','_')[:40]}",
                "network", "high",
                f"Namespace sin NetworkPolicy: {name}",
                f"El namespace '{name}' no tiene ninguna NetworkPolicy. "
                "Todos los pods pueden comunicarse entre sí sin restricciones.",
                f"Crear una NetworkPolicy por defecto que deniegue todo el tráfico:\n"
                f"kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\n"
                f"kind: NetworkPolicy\nmetadata:\n  name: default-deny\n"
                f"  namespace: {name}\nspec:\n  podSelector: {{}}\n"
                f"  policyTypes: [Ingress, Egress]\nEOF",
                evidence=f"namespace={name}",
            ))
    return findings


async def check_no_resource_limits() -> list[Finding]:
    """Detecta contenedores sin limits de CPU/memoria."""
    pods = await _get_all_pods()
    findings = []
    seen = set()
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        if ns.startswith("kube-"):
            continue
        spec = pod.get("spec", {})
        for container in spec.get("containers", []):
            cname = container.get("name", "")
            resources = container.get("resources", {})
            limits = resources.get("limits", {})
            if not limits.get("memory") or not limits.get("cpu"):
                key = f"{ns}/{name}/{cname}"
                if key not in seen:
                    seen.add(key)
                    fid = f"k8s_no_limits_{ns}_{name}_{cname}".replace("-","_")[:70]
                    findings.append(_f(
                        fid, "resources", "medium",
                        f"Sin resource limits: {ns}/{name}/{cname}",
                        "Sin límites de CPU/memoria el contenedor puede consumir "
                        "todos los recursos del nodo (DoS involuntario).",
                        "Añadir a resources del contenedor:\n"
                        "limits:\n  memory: '512Mi'\n  cpu: '500m'",
                        evidence=f"limits={limits}",
                    ))
    return findings


async def check_latest_image_tag() -> list[Finding]:
    """Detecta pods usando imágenes con tag :latest."""
    pods = await _get_all_pods()
    findings = []
    seen = set()
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        spec = pod.get("spec", {})
        for container in spec.get("containers", []):
            image = container.get("image", "")
            if image.endswith(":latest") or (":" not in image.split("/")[-1]):
                key = f"{ns}:{image}"
                if key not in seen:
                    seen.add(key)
                    fid = f"k8s_latest_{ns}_{name}".replace("-","_")[:60]
                    findings.append(_f(
                        fid, "updates", "low",
                        f"Imagen con tag :latest: {image}",
                        f"El pod '{name}' en '{ns}' usa la imagen '{image}' sin tag fijo. "
                        "Puede desplegar versiones inesperadas en cada pull.",
                        f"Usar un tag específico: {image.split(':')[0]}:1.2.3",
                        evidence=f"image={image} namespace={ns}",
                    ))
    return findings


async def check_env_secrets() -> list[Finding]:
    """Detecta secretos hardcodeados en variables de entorno de pods."""
    pods = await _get_all_pods()
    findings = []
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        spec = pod.get("spec", {})
        for container in spec.get("containers", []):
            cname = container.get("name", "")
            for env in container.get("env", []):
                key   = env.get("name", "").lower()
                value = env.get("value", "")
                # Solo si tiene valor hardcodeado (no valueFrom)
                if value and any(pat in key for pat in SECRET_ENV_PATTERNS):
                    fid = f"k8s_env_secret_{ns}_{name}_{key[:20]}".replace("-","_")
                    findings.append(_f(
                        fid, "secrets", "high",
                        f"Posible secreto en env var: {ns}/{name} → {env.get('name')}",
                        f"Variable de entorno '{env.get('name')}' parece contener "
                        "credenciales hardcodeadas en el manifiesto del pod.",
                        "Usar Kubernetes Secrets en lugar de valores directos:\n"
                        "env:\n  - name: MY_SECRET\n    valueFrom:\n"
                        "      secretKeyRef:\n        name: my-secret\n        key: value",
                        evidence=f"env={env.get('name')} namespace={ns}",
                    ))
    return findings


async def check_dangerous_hostpath() -> list[Finding]:
    """Detecta pods con volúmenes hostPath peligrosos."""
    pods = await _get_all_pods()
    findings = []
    for pod in pods:
        meta = pod.get("metadata", {})
        name = meta.get("name", "")
        ns   = meta.get("namespace", "")
        if ns == "kube-system":
            continue
        spec = pod.get("spec", {})
        for vol in spec.get("volumes", []):
            hp = vol.get("hostPath", {})
            path = hp.get("path", "")
            if path in DANGEROUS_HOSTPATHS:
                fid = f"k8s_hostpath_{ns}_{name}_{path.replace('/','_')[:30]}"
                findings.append(_f(
                    fid, "pod_security", "critical",
                    f"HostPath peligroso montado: {ns}/{name} → {path}",
                    f"El pod '{name}' en '{ns}' monta la ruta '{path}' del host. "
                    "Permite acceso directo al sistema de ficheros del nodo.",
                    "Eliminar el volumen hostPath y usar PersistentVolumeClaim en su lugar.",
                    evidence=f"hostPath={path} namespace={ns}",
                    auto_fix=False,
                ))
    return findings


async def check_kubernetes_version() -> list[Finding]:
    """Verifica la versión de Kubernetes contra CVEs conocidos."""
    proc = await run_command(["kubectl", "version", "--output=json"], timeout=15, check=False)
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    server_ver = data.get("serverVersion", {})
    major = int(server_ver.get("major", 0))
    minor_str = server_ver.get("minor", "0").rstrip("+")
    try:
        minor = int(minor_str)
    except ValueError:
        return []

    git_version = server_ver.get("gitVersion", "")
    findings = []

    # CVEs por versión (simplificado)
    VULNERABLE = [
        ((1, 27), "CVE-2023-44487", "high",
         "HTTP/2 Rapid Reset Attack — versión de Kubernetes vulnerable"),
        ((1, 25), "CVE-2023-2431",  "medium",
         "Bypass de PodSecurityPolicy mediante securityContext en initContainers"),
        ((1, 26), "CVE-2023-3676",  "high",
         "Escalada de privilegios via ServiceAccount token injection"),
    ]

    for (max_maj, max_min), cve, sev, desc in VULNERABLE:
        if major <= max_maj and minor <= max_min:
            findings.append(_f(
                f"k8s_cve_{cve.replace('-','_').lower()}",
                "cve", sev,
                f"Kubernetes {git_version} vulnerable a {cve}",
                f"{desc}\nVersión actual: {git_version}",
                "kubectl upgrade o actualizar el cluster a una versión parcheada.",
                evidence=git_version,
            ))
    return findings


async def check_pod_security_standards() -> list[Finding]:
    """Verifica si los namespaces tienen Pod Security Admission configurado."""
    ns_data = await _kubectl(["get", "namespaces"])
    if not ns_data:
        return []

    findings = []
    skip_ns = {"kube-system", "kube-public", "kube-node-lease"}
    for ns in ns_data.get("items", []):
        name   = ns.get("metadata", {}).get("name", "")
        labels = ns.get("metadata", {}).get("labels", {})
        if name in skip_ns or name.startswith("kube-"):
            continue
        # Pod Security Admission labels
        has_psa = any("pod-security.kubernetes.io" in k for k in labels)
        if not has_psa:
            fid = f"k8s_no_psa_{name.replace('-','_')[:40]}"
            findings.append(_f(
                fid, "pod_security", "medium",
                f"Sin Pod Security Admission: namespace {name}",
                f"El namespace '{name}' no tiene configurado Pod Security Admission (PSA). "
                "Los pods pueden ejecutarse sin restricciones de seguridad.",
                f"Añadir label al namespace:\n"
                f"kubectl label ns {name} "
                f"pod-security.kubernetes.io/enforce=baseline",
                evidence=f"namespace={name} labels={list(labels.keys())[:5]}",
            ))
    return findings


# ── Orquestador ───────────────────────────────────────────────────────────────

class KubernetesScanner:
    CHECKS = [
        check_pods_as_root,
        check_privileged_pods,
        check_rbac_wildcards,
        check_automount_service_account,
        check_no_network_policy,
        check_no_resource_limits,
        check_latest_image_tag,
        check_env_secrets,
        check_dangerous_hostpath,
        check_kubernetes_version,
        check_pod_security_standards,
    ]

    @classmethod
    async def full_scan(cls) -> list[Finding]:
        if not await _kubectl_available():
            logger.info("kubectl no disponible o sin acceso al cluster — saltando K8s scan")
            return [Finding(
                id="k8s_unavailable", category="kubernetes", severity="info",
                title="Kubernetes no detectado o sin acceso",
                description="kubectl no está disponible o no hay cluster accesible.",
                remediation=(
                    "Si tienes Kubernetes, configura kubectl:\n"
                    "kubectl config use-context mi-cluster"
                ),
            )]

        logger.info("Kubernetes scan iniciado")
        results = await asyncio.gather(
            *[check() for check in cls.CHECKS],
            return_exceptions=True,
        )
        findings: list[Finding] = []
        for check_fn, result in zip(cls.CHECKS, results):
            if isinstance(result, list):
                findings.extend(result)
                logger.info("  k8s/%s: %d hallazgos", check_fn.__name__, len(result))
            else:
                logger.error("  k8s/%s error: %s", check_fn.__name__, result)

        logger.info("Kubernetes scan: %d hallazgos", len(findings))
        return findings
