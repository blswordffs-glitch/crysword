from __future__ import annotations
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Mapping
from pathlib import Path
from typing import Any
LOCAL_CONFIG_PATH = Path(__file__).with_name("sageworker_config.json")
class SageWorkerError(RuntimeError):
    """Raised when the Windows-to-WSL Sage bridge fails."""
def user_config_path() -> Path:
    """Return the per-user configuration path."""
    if os.name == "nt":
        base = Path(
            os.environ.get(
                "APPDATA",
                Path.home() / "AppData" / "Roaming",
            )
        )
    else:
        base = Path(
            os.environ.get(
                "XDG_CONFIG_HOME",
                Path.home() / ".config",
            )
        )
    return base / "crysword" / "sageworker_config.json"
def load_sage_config(
    config_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    explicit_path = config_path or os.environ.get("SAGEWORKER_CONFIG")
    if explicit_path:
        candidates = [Path(explicit_path)]
    else:
        candidates = [
            user_config_path(),
            LOCAL_CONFIG_PATH,
        ]
    path = next(
        (candidate for candidate in candidates if candidate.exists()),
        None,
    )
    if path is None:
        expected = (
            Path(explicit_path)
            if explicit_path
            else user_config_path()
        )
        raise SageWorkerError(
            f"找不到 Sage 配置文件: {expected}. "
            "请先运行 `python sageworker.py --configure`。"
        )
    try:
        config = json.loads(
            path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError:
        raise SageWorkerError(
            f"Sage 配置文件不是合法 JSON: {path}"
        )

    if not isinstance(config, dict):
        raise SageWorkerError(
            "Sage 配置文件的根对象必须是 JSON object。"
        )
    return config
def _config_save_path(
    config_path: str | os.PathLike[str] | None,
) -> Path:
    return Path(
        config_path
        or os.environ.get("SAGEWORKER_CONFIG")
        or user_config_path()
    )
def save_sage_config(
    *,
    wsl_distribution: str,
    sage_path: str,
    timeout: float = 60.0,
    config_path: str | os.PathLike[str] | None = None,
) -> Path:
    path = _config_save_path(config_path)
    config = {
        "config_version": 1,
        "wsl_distribution": wsl_distribution,
        "sage_path": sage_path,
        "timeout": timeout,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return path
def configure_sage(
    *,
    wsl_distribution: str | None = None,
    sage_path: str | None = None,
    timeout: float | None = None,
    config_path: str | os.PathLike[str] | None = None,
    interactive: bool = True,
    test_connection: bool = True,
) -> Path:
    """Create the user configuration and optionally test Sage."""
    existing: dict[str, Any] = {}
    try:
        existing = load_sage_config(config_path)
    except SageWorkerError:
        pass
    if interactive:
        current_distribution = str(
            existing.get(
                "wsl_distribution",
                wsl_distribution or "Ubuntu",
            )
        )
        current_sage_path = str(
            existing.get(
                "sage_path",
                sage_path or "sage",
            )
        )
        current_timeout = str(
            existing.get("timeout", timeout or 60)
        )
        wsl_distribution = (
            input(
                f"WSL 发行版 [{current_distribution}]: "
            ).strip()
            or current_distribution
        )
        sage_path = (
            input(
                f"Sage 可执行文件路径 [{current_sage_path}]: "
            ).strip()
            or current_sage_path
        )
        timeout_text = (
            input(
                f"超时时间（秒）[{current_timeout}]: "
            ).strip()
            or current_timeout
        )
        timeout = float(timeout_text)
    else:
        wsl_distribution = wsl_distribution or str(
            existing.get("wsl_distribution", "Ubuntu")
        )
        sage_path = sage_path or str(
            existing.get("sage_path", "sage")
        )
        timeout = float(
            timeout
            if timeout is not None
            else existing.get("timeout", 60)
        )

    path = save_sage_config(
        wsl_distribution=wsl_distribution,
        sage_path=sage_path,
        timeout=timeout,
        config_path=config_path,
    )
    print(f"[sageworker] 配置已保存: {path}")

    if test_connection:
        check_sage_connection(
            config_path=path,
            show_status=True,
        )
    return path
def sage(
    source: str,
    data: Mapping[str, Any] | None = None,
    *,
    config_path: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
    show_status: bool = True,
) -> Any:
    """Execute source code in Sage and return its JSON result."""
    if not isinstance(source, str) or not source.strip():
        raise SageWorkerError(
            "Sage source must be a non-empty string."
        )

    config = load_sage_config(config_path)
    distribution = str(
        config.get("wsl_distribution", "Ubuntu")
    )
    sage_path = str(
        config.get(
            "sage_path",
            config.get("sage_command", "sage"),
        )
    )
    request_timeout = float(
        timeout
        if timeout is not None
        else config.get("timeout", 60.0)
    )

    command = [
        "wsl.exe",
        "--distribution",
        distribution,
        "--exec",
        sage_path,
        "-python",
        "-",
    ]
    request_json = json.dumps(
        dict(data or {}),
        ensure_ascii=True,
    )
    result_marker = "__CRYSWORD_RESULT__"
    error_marker = "__CRYSWORD_ERROR__"
    indented_source = textwrap.indent(
        source.strip(),
        "    ",
    )
    program = "\n".join(
        [
            "import json",
            f"request = json.loads({request_json!r})",
            "try:",
            indented_source,
            (
                f"    print({result_marker!r} + "
                "json.dumps(result, default=str), flush=True)"
            ),
            "except Exception as exc:",
            (
                "    error = "
                "{'error': f'{type(exc).__name__}: {exc}'}"
            ),
            (
                f"    print({error_marker!r} + "
                "json.dumps(error, ensure_ascii=True), flush=True)"
            ),
            "",
        ]
    )
    try:
        completed = subprocess.run(
            command,
            input=program,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=request_timeout,
            check=False,
        )
    except FileNotFoundError:
        error = SageWorkerError(
            "找不到 wsl.exe，请确认 WSL 已安装。"
        )
        if show_status:
            print(
                f"[sageworker] 调用失败: {error}",
                file=sys.stderr,
            )
        raise error
    except subprocess.TimeoutExpired:
        error = SageWorkerError(
            f"Sage 运行超过 {request_timeout:g} 秒。"
        )
        if show_status:
            print(
                f"[sageworker] 调用失败: {error}",
                file=sys.stderr,
            )
        raise error
    if completed.returncode != 0:
        if completed.returncode in (-1, 0xFFFFFFFF):
            error = SageWorkerError(
                "wsl.exe 返回 E_ACCESSDENIED。"
                "请检查 WSL 服务和发行版权限。"
            )
        else:
            detail = (
                completed.stderr.strip()
                or completed.stdout.strip()
            )
            error = SageWorkerError(
                "Sage worker 执行失败，"
                f"返回码为 {completed.returncode}: {detail}"
            )
        if show_status:
            print(
                f"[sageworker] 调用失败: {error}",
                file=sys.stderr,
            )
        raise error
    for line in reversed(completed.stdout.splitlines()):
        if line.startswith(result_marker):
            try:
                value = json.loads(
                    line[len(result_marker):]
                )
            except json.JSONDecodeError:
                raise SageWorkerError(
                    f"Sage 返回结果不是合法 JSON: {line!r}"
                )

            if show_status:
                print(
                    "[sageworker] 调用成功: "
                    f"{distribution} / {sage_path}"
                )
            return value

        if line.startswith(error_marker):
            try:
                error_text = json.loads(
                    line[len(error_marker):]
                ).get(
                    "error",
                    "Sage source failed.",
                )
            except json.JSONDecodeError:
                error_text = line[len(error_marker):]
            error = SageWorkerError(str(error_text))
            if show_status:
                print(
                    f"[sageworker] 调用失败: {error}",
                    file=sys.stderr,
                )
            raise error
    error = SageWorkerError(
        "Sage 没有返回结果标记。"
        f"stdout={completed.stdout!r}"
    )
    if show_status:
        print(
            f"[sageworker] 调用失败: {error}",
            file=sys.stderr,
        )
    raise error
def check_sage_connection(
    *,
    config_path: str | os.PathLike[str] | None = None,
    timeout: float | None = None,
    show_status: bool = True,
) -> bool:
    """Check that the configured WSL/Sage command can run."""
    try:
        config = load_sage_config(config_path)
    except SageWorkerError as error:
        if show_status:
            print(
                f"[sageworker] 环境检查失败: {error}",
                file=sys.stderr,
            )
        return False
    try:
        sage(
            "result = {'status': 'ok'}",
            config_path=config_path,
            timeout=timeout,
            show_status=False,
        )
    except SageWorkerError as error:
        if show_status:
            print(
                f"[sageworker] Sage 连接失败: {error}",
                file=sys.stderr,
            )
        return False
    if show_status:
        distribution = config.get(
            "wsl_distribution",
            "Ubuntu",
        )
        sage_path = config.get(
            "sage_path",
            config.get("sage_command", "sage"),
        )
        saved_path = config_path or os.environ.get(
            "SAGEWORKER_CONFIG",
            user_config_path(),
        )
        print("[sageworker] Sage 环境检查成功。")
        print(f"[sageworker] WSL 发行版: {distribution}")
        print(f"[sageworker] Sage 路径: {sage_path}")
        print(f"[sageworker] 配置文件: {saved_path}")
    return True
if __name__ == "__main__":
    if "--configure" in sys.argv:
        configure_sage()
    elif "--check" in sys.argv:
        check_sage_connection()
    else:
        print("用法: python sageworker.py --configure")
        print("     python sageworker.py --check")
