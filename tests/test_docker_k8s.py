"""Tests de los módulos Docker y Kubernetes."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cyberhound.scanners.docker_scan import (
    DockerScanner,
    _docker_available,
    check_containers_as_root,
    check_dangerous_mounts,
    check_docker_socket_mounted,
    check_privileged_containers,
    check_secret_env_vars,
)
from cyberhound.scanners.kubernetes_scan import (
    KubernetesScanner,
    _kubectl_available,
    check_env_secrets,
    check_latest_image_tag,
    check_no_network_policy,
    check_no_resource_limits,
    check_pods_as_root,
    check_privileged_pods,
)
from cyberhound.core.security import InputValidator, ValidationError


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_container(name="app", user="", privileged=False, caps=None, env=None, image="myapp:1.0"):
    return {
        "name": name,
        "image": image,
        "securityContext": {
            **({"privileged": True} if privileged else {}),
            **({"User": user} if user else {}),
        },
        "env": env or [],
        "resources": {},
    }


def make_pod(name="mypod", ns="default", containers=None, volumes=None):
    return {
        "metadata": {"name": name, "namespace": ns},
        "spec": {
            "containers": containers or [make_container()],
            "volumes": volumes or [],
            "securityContext": {},
        },
    }


def docker_inspect_container(user="", privileged=False, caps=None, mounts=None, env=None):
    return [{
        "Name": "/mycontainer",
        "Config": {
            "User": user,
            "Env": env or [],
        },
        "HostConfig": {
            "Privileged": privileged,
            "CapAdd": caps or [],
        },
        "Mounts": mounts or [],
    }]


# ── Docker tests ──────────────────────────────────────────────────────────────

class TestDockerAvailability:

    @pytest.mark.asyncio
    async def test_unavailable_when_no_command(self):
        with patch("cyberhound.scanners.docker_scan.command_exists", return_value=False):
            assert not await _docker_available()

    @pytest.mark.asyncio
    async def test_unavailable_when_daemon_down(self):
        proc = MagicMock(returncode=1, stdout="", stderr="Cannot connect")
        with patch("cyberhound.scanners.docker_scan.command_exists", return_value=True), \
             patch("cyberhound.scanners.docker_scan.run_command", new_callable=AsyncMock, return_value=proc):
            assert not await _docker_available()

    @pytest.mark.asyncio
    async def test_available_when_daemon_up(self):
        proc = MagicMock(returncode=0, stdout="{}", stderr="")
        with patch("cyberhound.scanners.docker_scan.command_exists", return_value=True), \
             patch("cyberhound.scanners.docker_scan.run_command", new_callable=AsyncMock, return_value=proc):
            assert await _docker_available()


class TestDockerContainersAsRoot:

    @pytest.mark.asyncio
    async def test_detects_root_container(self):
        containers_json = json.dumps([{"ID": "abc123", "Names": "myapp"}])
        inspect = docker_inspect_container(user="")  # sin usuario = root
        proc_ps = MagicMock(returncode=0, stdout=containers_json)

        with patch("cyberhound.scanners.docker_scan._docker_json") as mock_dj:
            async def side_effect(args):
                if "ps" in args:
                    return [{"ID": "abc123", "Names": "myapp"}]
                if "inspect" in args:
                    return [{"Config": {"User": ""}, "HostConfig": {"Privileged": False, "CapAdd": []}, "Mounts": [], "Name": "/myapp"}]
                return None
            mock_dj.side_effect = side_effect
            findings = await check_containers_as_root()
        assert len(findings) >= 1
        assert findings[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_findings_when_no_containers(self):
        with patch("cyberhound.scanners.docker_scan._docker_json", new_callable=AsyncMock, return_value=[]):
            findings = await check_containers_as_root()
        assert findings == []


class TestDockerPrivileged:

    @pytest.mark.asyncio
    async def test_detects_privileged_container(self):
        with patch("cyberhound.scanners.docker_scan._docker_json") as mock_dj:
            async def side_effect(args):
                if "ps" in args and "-q" in args:
                    return ["abc123"]
                if "inspect" in args:
                    return docker_inspect_container(privileged=True)
                return None
            mock_dj.side_effect = side_effect
            findings = await check_privileged_containers()
        assert any(f.severity == "critical" for f in findings)

    @pytest.mark.asyncio
    async def test_no_findings_when_no_containers(self):
        with patch("cyberhound.scanners.docker_scan._docker_json", new_callable=AsyncMock, return_value=[]):
            findings = await check_privileged_containers()
        assert findings == []


class TestDockerSocketMounted:

    @pytest.mark.asyncio
    async def test_detects_socket_mount(self):
        with patch("cyberhound.scanners.docker_scan._docker_json") as mock_dj:
            async def side_effect(args):
                if "ps" in args and "-q" in args:
                    return ["abc123"]
                if "inspect" in args:
                    return [{
                        "Name": "/dind",
                        "Config": {"User": "", "Env": []},
                        "HostConfig": {"Privileged": False, "CapAdd": []},
                        "Mounts": [{"Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}],
                    }]
                return None
            mock_dj.side_effect = side_effect
            findings = await check_docker_socket_mounted()
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert "escape" in findings[0].category


class TestDockerEnvSecrets:

    @pytest.mark.asyncio
    async def test_detects_password_in_env(self):
        with patch("cyberhound.scanners.docker_scan._docker_json") as mock_dj:
            async def side_effect(args):
                if "ps" in args and "-q" in args:
                    return ["abc123"]
                if "inspect" in args:
                    return [{
                        "Name": "/myapp",
                        "Config": {"User": "", "Env": ["DATABASE_PASSWORD=supersecret123", "PORT=8080"]},
                        "HostConfig": {"Privileged": False, "CapAdd": []},
                        "Mounts": [],
                    }]
                return None
            mock_dj.side_effect = side_effect
            findings = await check_secret_env_vars()
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "secrets" in findings[0].category

    @pytest.mark.asyncio
    async def test_no_findings_with_safe_env(self):
        with patch("cyberhound.scanners.docker_scan._docker_json") as mock_dj:
            async def side_effect(args):
                if "ps" in args and "-q" in args:
                    return ["abc123"]
                if "inspect" in args:
                    return [{
                        "Name": "/myapp",
                        "Config": {"User": "", "Env": ["PORT=8080", "ENV=production"]},
                        "HostConfig": {"Privileged": False, "CapAdd": []},
                        "Mounts": [],
                    }]
                return None
            mock_dj.side_effect = side_effect
            findings = await check_secret_env_vars()
        assert findings == []


class TestDockerFullScan:

    @pytest.mark.asyncio
    async def test_returns_unavailable_when_no_docker(self):
        with patch("cyberhound.scanners.docker_scan._docker_available",
                   new_callable=AsyncMock, return_value=False), \
             patch("cyberhound.scanners.kubernetes_scan.KubernetesScanner.full_scan",
                   new_callable=AsyncMock, return_value=[]):
            findings = await DockerScanner.full_scan()
        assert any(f.id == "docker_unavailable" for f in findings)

    @pytest.mark.asyncio
    async def test_includes_k8s_findings(self):
        from cyberhound.core.models import Finding
        k8s_finding = Finding(
            id="k8s_test", category="kubernetes/rbac", severity="critical",
            title="Test K8s", description="", remediation=""
        )
        with patch("cyberhound.scanners.docker_scan._docker_available",
                   new_callable=AsyncMock, return_value=False), \
             patch("cyberhound.scanners.kubernetes_scan.KubernetesScanner.full_scan",
                   new_callable=AsyncMock, return_value=[k8s_finding]):
            findings = await DockerScanner.full_scan(scan_k8s=True)
        assert any(f.id == "k8s_test" for f in findings)

    @pytest.mark.asyncio
    async def test_skips_k8s_when_disabled(self):
        with patch("cyberhound.scanners.docker_scan._docker_available",
                   new_callable=AsyncMock, return_value=False):
            findings = await DockerScanner.full_scan(scan_k8s=False)
        # Solo debe haber el finding de docker_unavailable, sin K8s
        assert not any(f.category.startswith("kubernetes") for f in findings)


# ── Kubernetes tests ──────────────────────────────────────────────────────────

class TestKubernetesAvailability:

    @pytest.mark.asyncio
    async def test_unavailable_when_no_kubectl(self):
        with patch("cyberhound.scanners.kubernetes_scan.command_exists", return_value=False):
            assert not await _kubectl_available()


class TestK8sPodsAsRoot:

    @pytest.mark.asyncio
    async def test_detects_pod_as_root(self):
        pods = [make_pod(containers=[make_container(user="")])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_pods_as_root()
        assert len(findings) >= 1
        assert findings[0].severity == "high"
        assert "pod_security" in findings[0].category

    @pytest.mark.asyncio
    async def test_no_findings_when_non_root(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_pods_as_root()
        assert findings == []


class TestK8sPrivilegedPods:

    @pytest.mark.asyncio
    async def test_detects_privileged(self):
        container = {
            "name": "privileged-app", "image": "myapp:1.0",
            "securityContext": {"privileged": True},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_privileged_pods()
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_no_findings_when_not_privileged(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "securityContext": {"privileged": False},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_privileged_pods()
        assert findings == []


class TestK8sNoResourceLimits:

    @pytest.mark.asyncio
    async def test_detects_missing_limits(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "resources": {},  # sin limits
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_no_resource_limits()
        assert len(findings) >= 1
        assert findings[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_no_findings_with_limits(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "resources": {"limits": {"memory": "512Mi", "cpu": "500m"}},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_no_resource_limits()
        assert findings == []


class TestK8sLatestTag:

    @pytest.mark.asyncio
    async def test_detects_latest_tag(self):
        pods = [make_pod(containers=[make_container(image="nginx:latest")])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_latest_image_tag()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_detects_no_tag(self):
        pods = [make_pod(containers=[make_container(image="nginx")])]  # sin tag = latest implícito
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_latest_image_tag()
        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_no_findings_with_specific_tag(self):
        pods = [make_pod(containers=[make_container(image="nginx:1.25.3")])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_latest_image_tag()
        assert findings == []


class TestK8sEnvSecrets:

    @pytest.mark.asyncio
    async def test_detects_hardcoded_secret(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "env": [{"name": "DATABASE_PASSWORD", "value": "supersecret"}],
            "resources": {},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_env_secrets()
        assert len(findings) == 1
        assert findings[0].severity == "high"

    @pytest.mark.asyncio
    async def test_no_findings_with_secretkeyref(self):
        container = {
            "name": "app", "image": "myapp:1.0",
            "env": [{"name": "DATABASE_PASSWORD", "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}}}],
            "resources": {},
        }
        pods = [make_pod(containers=[container])]
        with patch("cyberhound.scanners.kubernetes_scan._get_all_pods",
                   new_callable=AsyncMock, return_value=pods):
            findings = await check_env_secrets()
        assert findings == []


class TestK8sNoNetworkPolicy:

    @pytest.mark.asyncio
    async def test_detects_namespace_without_policy(self):
        ns_data = {"items": [
            {"metadata": {"name": "my-app"}},
            {"metadata": {"name": "kube-system"}},  # debe ignorarse
        ]}
        np_data = {"items": []}  # sin políticas

        with patch("cyberhound.scanners.kubernetes_scan._kubectl") as mock_k:
            async def side_effect(args):
                if "namespaces" in args:
                    return ns_data
                if "networkpolicies" in args:
                    return np_data
                return None
            mock_k.side_effect = side_effect
            findings = await check_no_network_policy()

        assert len(findings) == 1
        assert findings[0].id.startswith("k8s_no_netpol_my_app")

    @pytest.mark.asyncio
    async def test_no_findings_when_policy_exists(self):
        ns_data = {"items": [{"metadata": {"name": "my-app"}}]}
        np_data = {"items": [{"metadata": {"name": "deny-all", "namespace": "my-app"}}]}

        with patch("cyberhound.scanners.kubernetes_scan._kubectl") as mock_k:
            async def side_effect(args):
                if "namespaces" in args:
                    return ns_data
                if "networkpolicies" in args:
                    return np_data
                return None
            mock_k.side_effect = side_effect
            findings = await check_no_network_policy()
        assert findings == []


class TestK8sFullScanUnavailable:

    @pytest.mark.asyncio
    async def test_returns_info_when_no_kubectl(self):
        with patch("cyberhound.scanners.kubernetes_scan._kubectl_available",
                   new_callable=AsyncMock, return_value=False):
            findings = await KubernetesScanner.full_scan()
        assert len(findings) == 1
        assert findings[0].id == "k8s_unavailable"
        assert findings[0].severity == "info"


# ── InputValidator — nuevos parámetros Docker ─────────────────────────────────

class TestDockerWSValidation:

    def test_docker_task_accepted(self):
        msg = InputValidator.ws_message({"task": "docker"})
        assert msg["task"] == "docker"
        assert msg["scan_images_cve"] is True
        assert msg["scan_k8s"] is True

    def test_docker_scan_flags(self):
        msg = InputValidator.ws_message({
            "task": "docker",
            "scan_images_cve": False,
            "scan_k8s": False,
        })
        assert msg["scan_images_cve"] is False
        assert msg["scan_k8s"] is False
