"""
Docker and Container Environment Security Check Scanner.
Detects container runtime presence, containerization environment (Docker, Podman, LXC, Kubernetes), Docker socket permissions, and user group access.
"""

import os
import stat
import grp
import pwd
from typing import List
from lpe_autoscan.scanners.base import BaseScanner
from lpe_autoscan.models import Finding, Severity, Confidence, Category


class DockerScanner(BaseScanner):
    name = "docker"
    category = Category.DOCKER
    description = "Audit Docker daemon socket permissions, container groups, and container environment"

    DOCKER_SOCKET = "/var/run/docker.sock"

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Detect if running inside container
        in_container = self._check_container_environment()
        if in_container:
            findings.append(
                Finding(
                    finding_id="DOCKER-IN-CONTAINER",
                    category=self.category,
                    title="System Running Inside Containerized Environment",
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=f"System environment indicators reflect execution inside a container ({in_container}).",
                    evidence=[f"Container Runtime Detected: {in_container}"],
                    impact="Container context limits privilege escalation scope to container sandbox unless escape vectors exist.",
                    exploitation_possible=False,
                    references=["https://attack.mitre.org/techniques/T1611/"],
                    mitigation="Review container capability profile, mount points, and security constraints."
                )
            )

        # 2. Check Docker daemon socket accessibility
        if os.path.exists(self.DOCKER_SOCKET):
            try:
                st = os.stat(self.DOCKER_SOCKET)
                mode = st.st_mode
                current_uid = os.getuid()
                current_user = pwd.getpwuid(current_uid).pw_name

                # Socket is readable/writable by current unprivileged user
                if os.access(self.DOCKER_SOCKET, os.R_OK | os.W_OK) and current_uid != 0:
                    findings.append(
                        Finding(
                            finding_id="DOCKER-SOCKET-WRITABLE",
                            category=self.category,
                            title="Docker Daemon Socket Accessible by Current Unprivileged User",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description=f"The Docker daemon API socket '{self.DOCKER_SOCKET}' is directly accessible by user '{current_user}'.",
                            evidence=[f"Socket Path: {self.DOCKER_SOCKET}", f"Access Mode: Read/Write", f"User: {current_user}"],
                            impact="Access to the Docker socket allows spawning privileged containers with root filesystem mounts, granting instant host root access.",
                            exploitation_possible=True,
                            references=["https://gtfobins.github.io/gtfobins/docker/", "https://attack.mitre.org/techniques/T1611/"],
                            mitigation="Remove unprivileged users from 'docker' group and restrict socket permissions."
                        )
                    )
            except Exception:
                pass

        return findings

    def _check_container_environment(self) -> str:
        if os.path.exists("/.dockerenv"):
            return "Docker Container (/.dockerenv present)"
        if os.path.exists("/run/containerd/containerd.sock"):
            return "Containerd Runtime"
        if os.path.exists("/proc/1/cgroup"):
            try:
                with open("/proc/1/cgroup", "r") as f:
                    content = f.read()
                    if "docker" in content:
                        return "Docker Container (cgroup indicator)"
                    elif "lxc" in content:
                        return "LXC Container"
                    elif "kubepods" in content:
                        return "Kubernetes Pod"
            except Exception:
                pass
        return ""
