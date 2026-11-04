import os


def artifacts_base_dir() -> str:
    """Shared artifact root.

    Set ARTIFACTS_DIR (e.g. /app/artifacts on the compose shared volume) so the
    API and worker containers agree on where per-task artifacts live.
    """
    return os.path.abspath(os.getenv("ARTIFACTS_DIR", "artifacts"))


def resolve_task_folder(base_dir: str, task_id: str) -> str:
    """The one place a task ID becomes a path: <base_dir>/<task_id>, traversal-safe.

    Raises ValueError for IDs that aren't [A-Za-z0-9_-]+ and PermissionError if the
    result would escape base_dir.
    """
    # [P3] Validate task_id is a safe UUID before joining paths.
    if not task_id or not all(c.isalnum() or c in "-_" for c in task_id):
        raise ValueError("Unsafe Task ID detected. Only UUIDs allowed.")

    base = os.path.abspath(base_dir)
    path = os.path.abspath(os.path.join(base, task_id))
    # Compare against base + separator to avoid the "/app/artifacts_evil" prefix edge.
    if not path.startswith(base + os.sep):
        raise PermissionError("Path traversal attempt blocked!")
    return path


def task_folder_for(task_id: str) -> str:
    """Absolute artifact folder for a task under the shared root (API side)."""
    return resolve_task_folder(artifacts_base_dir(), task_id)


class ArtifactManager:
    def __init__(self, base_dir=None):
        # Strictly resolve absolute path to prevent traversal escape.
        self.base_dir = os.path.abspath(base_dir) if base_dir else artifacts_base_dir()
        os.makedirs(self.base_dir, exist_ok=True)

    def create_task_folder(self, task_id: str) -> str:
        task_path = resolve_task_folder(self.base_dir, task_id)
        os.makedirs(task_path, exist_ok=True)
        return task_path

    def get_task_manifest(self, task_id: str) -> dict:
        try:
            safe_path = resolve_task_folder(self.base_dir, task_id)
        except (ValueError, PermissionError):
            return {"artifacts": []}
        if not os.path.isdir(safe_path):
            return {"artifacts": []}

        # Recurse so nested folders (e.g. screenshots/) are included in the manifest;
        # rel_path is relative to the task folder and matches /tasks/{id}/artifacts/{path}.
        files = []
        for root, _dirs, names in os.walk(safe_path):
            for name in sorted(names):
                full = os.path.join(root, name)
                files.append({
                    "name": name,
                    "rel_path": os.path.relpath(full, safe_path),
                })
        return {"artifacts": files}
