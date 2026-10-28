"""Zero-Config Auto-Bootstrap for God's Eye (𓂀) OSINT Platform."""

import shutil
from pathlib import Path
from typing import Any


def ensure_zero_config_environment(project_root: Path | None = None) -> dict[str, Any]:
    """Ensure directories, default .env file, and local storage exist with zero manual setup."""
    root = project_root or Path(__file__).resolve().parent.parent.parent
    home_dir = Path.home() / ".godseye"
    home_dir.mkdir(parents=True, exist_ok=True)

    env_path = root / ".env"
    env_example = root / ".env.example"
    created_env = False
    if not env_path.exists() and env_example.exists():
        try:
            shutil.copyfile(env_example, env_path)
            created_env = True
        except OSError:
            pass

    return {
        "project_root": str(root),
        "data_dir": str(home_dir),
        "db_path": str(home_dir / "godseye.db"),
        "env_file": str(env_path),
        "created_env": created_env,
    }
