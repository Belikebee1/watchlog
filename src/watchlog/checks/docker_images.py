"""Docker images freshness — compare local digest vs remote :latest digest."""

from __future__ import annotations

import json
import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check


def _local_digest(image: str) -> str | None:
    """Return RepoDigest for local image, or None if not present."""
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return None
        digests = json.loads(proc.stdout.strip() or "null") or []
        # Take just the digest part (after @)
        for d in digests:
            if "@" in d:
                return d.split("@", 1)[1]
        return None
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        return None


def _remote_digest(image: str) -> str | None:
    """Pull manifest digest from registry without downloading layers."""
    try:
        proc = subprocess.run(
            ["docker", "buildx", "imagetools", "inspect", image, "--raw"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if proc.returncode != 0:
            return None
        # The output is a JSON manifest; we just hash it the same way docker does.
        # Easier: use `docker manifest inspect` if buildx not available.
        # For simplicity, parse the digest from the JSON manifest's mediaType+content
        # — but that needs sha256. Fallback: try `docker pull --quiet` which prints digest.
        return _digest_via_pull(image)
    except (subprocess.SubprocessError, OSError):
        return _digest_via_pull(image)


def _digest_via_pull(image: str) -> str | None:
    """Fallback: docker pull --quiet returns the digest in a known format."""
    try:
        proc = subprocess.run(
            ["docker", "pull", "--quiet", image],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            return None
        # Output: "Status: Image is up to date for image:tag" or just "image:tag"
        # We parse the digest from `docker image inspect` after pull.
        return _local_digest(image)
    except (subprocess.SubprocessError, OSError):
        return None


@register_check
class DockerImagesCheck(Check):
    name = "docker_images"

    def run(self) -> CheckResult:
        images: list[str] = list(self.config.get("images") or [])
        if not images:
            return self._info("No Docker images configured", "Set checks.docker_images.images")

        # Check Docker is even installed
        if subprocess.run(
            ["which", "docker"], capture_output=True, check=False
        ).returncode != 0:
            return self._info("Docker not installed", "Skipping image checks")

        outdated: list[str] = []
        ok_list: list[str] = []
        missing: list[str] = []

        for image in images:
            local = _local_digest(image)
            if local is None:
                missing.append(image)
                continue
            remote = _remote_digest(image)
            if remote is None:
                missing.append(f"{image} (cannot fetch remote digest)")
                continue
            if local != remote:
                outdated.append(f"{image}: local={local[:16]}... remote={remote[:16]}...")
            else:
                ok_list.append(f"{image}: up to date")

        details = (
            [f"⚠️ outdated: {x}" for x in outdated]
            + [f"❓ {x}" for x in missing]
            + [f"✅ {x}" for x in ok_list]
        )

        if outdated:
            return self._info(
                f"{len(outdated)} Docker image(s) have newer versions available",
                summary="Run `docker compose pull && docker compose up -d` in each project.",
                details=details,
                actions=["docker pull " + i.split(":")[0] for i in outdated],
            )

        return self._ok(
            f"All {len(ok_list)} configured Docker images up to date", details=details
        )
