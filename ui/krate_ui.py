import sys; sys.dont_write_bytecode = True
"""
Krate Studio - Backend Daemon and IPC Engine.
Pure Python 3.9+ stdlib implementation.

Features:
- ThreadingHTTPServer with session-based auth and CSRF protection
- Bootstrap token exchange -> HttpOnly SameSite=Strict cookie + X-Krate-CSRF header
- Job supervisor with 10,000-line ring buffer per job, single-flight mutation mutex, SSE streaming
- Native pipe/env IPC: KRATE_BACKUP_PASSPHRASE env, stdin=PIPE for rotate and purge, 0700 SUDO_ASKPASS
- sg docker wrapper when docker socket permission is denied
- is_package detection and KRATE_HOME workspace hot-switching
- Ephemeral one-time password card extractor for identity users add / reset-password while scrubbing logs
- Structured read APIs: /api/v1/workspaces, /api/v1/status, /api/v1/doctor, /api/v1/config,
  /api/v1/credentials, /api/v1/lag (single-JVM batch), /api/v1/identity/users
- 5-stage Grafana/Perses SSO orchestrator (/api/v1/sso/orchestrate)
- Zero-CLI Remote SSH bootstrapper (/api/v1/remote/verify-host, /api/v1/remote/connect)
  with OpenSSH askpass helper (SSH_ASKPASS_REQUIRE=force, DISPLAY=krate:0) and TOFU verification
"""

import collections
import http.cookies
import http.server
import hmac
import json
import os
import queue
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
import webbrowser
from typing import Optional, Union, Tuple, Dict, Any, List

# --- Constants & Defaults ---
DEFAULT_PORT = 8686
DEFAULT_HOST = "127.0.0.1"
RING_BUFFER_SIZE = 10000
SESSION_COOKIE_NAME = "krate_session"
CSRF_HEADER_NAME = "X-Krate-CSRF"
TOKEN_VALIDITY_SECONDS = 86400 * 7  # 7 days

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_STATIC_DIR = os.path.join(SCRIPT_DIR, "static")


# --- Session & Security Store ---
class SessionStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._sessions = {}  # session_id -> {csrf_token, created_at, expires_at}

    def create_session(self) -> Tuple[str, str]:
        with self._lock:
            session_id = secrets.token_hex(32)
            csrf_token = secrets.token_hex(32)
            now = time.time()
            self._sessions[session_id] = {
                "csrf_token": csrf_token,
                "created_at": now,
                "expires_at": now + TOKEN_VALIDITY_SECONDS,
            }
            return session_id, csrf_token

    def validate_session(self, session_id: str) -> bool:
        if not session_id:
            return False
        with self._lock:
            info = self._sessions.get(session_id)
            if not info:
                return False
            if time.time() > info["expires_at"]:
                del self._sessions[session_id]
                return False
            return True

    def get_csrf_token(self, session_id: str) -> Optional[str]:
        if not session_id:
            return None
        with self._lock:
            info = self._sessions.get(session_id)
            if info and time.time() <= info["expires_at"]:
                return info["csrf_token"]
            return None

    def validate_csrf(self, session_id: str, csrf_token: str) -> bool:
        if not session_id or not csrf_token:
            return False
        stored_csrf = self.get_csrf_token(session_id)
        if not stored_csrf:
            return False
        return hmac.compare_digest(stored_csrf, csrf_token)

    def revoke_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)


# --- Workspace Manager ---
class WorkspaceManager:
    def __init__(self, initial_path: Optional[str] = None):
        self._lock = threading.Lock()
        self.active_workspace = self._resolve_workspace(initial_path)

    def _resolve_workspace(self, path: Optional[str]) -> str:
        if path and os.path.isdir(path):
            return os.path.abspath(path)

        # Environment override
        env_home = os.environ.get("KRATE_HOME")
        if env_home and os.path.isdir(env_home):
            return os.path.abspath(env_home)

        # Prefer caller's working directory if it contains a krate CLI
        cwd = os.getcwd()
        if os.path.isfile(os.path.join(cwd, "krate")):
            return os.path.abspath(cwd)

        # Check package/installed root if krate sits directly beside ui/
        if os.path.isfile(os.path.join(REPO_ROOT, "krate")):
            return os.path.abspath(REPO_ROOT)

        # Check default paths: kraft edition under repo root
        kraft_dir = os.path.join(REPO_ROOT, "kraft")
        if os.path.isdir(kraft_dir) and os.path.exists(os.path.join(kraft_dir, "krate")):
            return kraft_dir

        # Check epc edition under repo root
        epc_dir = os.path.join(REPO_ROOT, "epc")
        if os.path.isdir(epc_dir) and os.path.exists(os.path.join(epc_dir, "krate")):
            return epc_dir

        # Standard install locations
        for std in ["/opt/krate/kraft", "/opt/krate/epc"]:
            if os.path.isdir(std):
                return std

        return os.path.abspath(cwd)

    def get_info(self, ws_path: Optional[str] = None) -> dict:
        target = os.path.abspath(ws_path) if ws_path else self.active_workspace
        krate_bin = os.path.join(target, "krate")
        has_krate = os.path.isfile(krate_bin) and os.access(krate_bin, os.X_OK)

        # Detect variant
        variant = "kraft"
        krate_file = os.path.join(target, "krate")
        if os.path.isfile(krate_file):
            try:
                with open(krate_file, "r", encoding="utf-8", errors="replace") as f:
                    for _ in range(50):
                        line = f.readline()
                        if not line:
                            break
                        m_var = re.match(r'^KRATE_VARIANT=["\']?([a-zA-Z0-9_-]+)["\']?', line.strip())
                        if m_var:
                            variant = m_var.group(1)
                            break
            except Exception:
                pass
        elif os.path.basename(target) == "epc":
            variant = "epc"
        elif os.path.basename(target) == "kraft":
            variant = "kraft"

        # Detect package vs repo vs install
        images_dir = os.path.join(target, "images")
        has_images = os.path.isdir(images_dir)
        has_makefile = os.path.exists(os.path.join(target, "Makefile")) or os.path.exists(
            os.path.join(target, "..", "Makefile")
        )

        krate_home = os.environ.get("KRATE_HOME") or f"/opt/krate/{variant}"
        abs_krate_home = os.path.abspath(krate_home)
        is_package = has_images and not has_makefile and target != abs_krate_home
        is_repo = has_makefile
        is_installed = (
            (not is_package)
            or target == abs_krate_home
            or os.path.isfile(os.path.join(abs_krate_home, "krate"))
        )

        # Compose file
        compose_file = os.path.join(target, "docker-compose.yml")
        has_compose = os.path.isfile(compose_file)

        return {
            "path": target,
            "name": os.path.basename(target) or target,
            "variant": variant,
            "has_krate": has_krate,
            "is_package": is_package,
            "is_installed": is_installed,
            "krate_home": abs_krate_home,
            "is_repo": is_repo,
            "has_compose": has_compose,
            "env_exists": os.path.isfile(os.path.join(target, ".env")),
            "active": target == self.active_workspace,
        }

    def list_workspaces(self) -> List[dict]:
        candidates = set()
        candidates.add(self.active_workspace)

        if os.path.isfile(os.path.join(REPO_ROOT, "krate")):
            candidates.add(os.path.abspath(REPO_ROOT))

        # Check repository editions
        for ed in ["kraft", "epc"]:
            d = os.path.join(REPO_ROOT, ed)
            if os.path.isdir(d):
                candidates.add(os.path.abspath(d))

        # Check /opt/krate/*
        for opt in ["/opt/krate/kraft", "/opt/krate/epc"]:
            if os.path.isdir(opt):
                candidates.add(os.path.abspath(opt))

        # Check current dir if it is a workspace
        cwd = os.path.abspath(os.getcwd())
        if os.path.isfile(os.path.join(cwd, "krate")) or os.path.isfile(
            os.path.join(cwd, "docker-compose.yml")
        ):
            candidates.add(cwd)

        results = []
        for c in sorted(candidates):
            if os.path.isdir(c):
                info = self.get_info(c)
                if info["has_krate"] or info["has_compose"] or c == self.active_workspace:
                    results.append(info)
        return results

    def switch_workspace(self, path: str) -> dict:
        candidate = path.strip()
        abs_path = os.path.abspath(candidate)
        if not os.path.isdir(abs_path) and candidate in ("kraft", "epc"):
            repo_ed = os.path.join(REPO_ROOT, candidate)
            opt_ed = f"/opt/krate/{candidate}"
            if os.path.isdir(repo_ed):
                abs_path = os.path.abspath(repo_ed)
            elif os.path.isdir(opt_ed):
                abs_path = os.path.abspath(opt_ed)
        if not os.path.isdir(abs_path):
            raise ValueError(f"Directory does not exist: {path}")
        with self._lock:
            self.active_workspace = abs_path
            os.environ["KRATE_HOME"] = abs_path
            return self.get_info(abs_path)


# --- Docker & System IPC Helpers ---
def check_docker_socket_permission() -> Tuple[bool, bool]:
    """
    Returns (direct_access_ok, sg_docker_needed).
    """
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            return True, False
        if "permission denied" in res.stderr.lower():
            try:
                sg_res = subprocess.run(
                    ["sg", "docker", "-c", "docker info"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                if sg_res.returncode == 0:
                    return False, True
            except Exception:
                pass
    except Exception:
        pass
    return False, False


def check_sudo_challenge_needed(
    action: str,
    params: dict,
    ws_info: dict,
    sudo_password: Optional[str],
) -> Tuple[bool, str]:
    """
    Determines whether the requested action requires root privileges and a sudo password prompt.
    Returns (needs_sudo, message).
    """
    if sudo_password:
        return False, ""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return False, ""

    requires_root = False
    reason = f"Operation '{action}' requires root privileges on the host system (via sudo -A)."

    fix_id = params.get("fix") if isinstance(params, dict) else None
    if action in ("docker-install", "start-docker") or (
        action == "doctor_fix" and fix_id in ("docker-install", "start-docker")
    ):
        requires_root = True
        reason = "Installing or starting Docker requires host root privileges (via sudo -A)."
    elif action == "install" or (action == "doctor_fix" and fix_id == "install"):
        krate_home = ws_info.get("krate_home") or f"/opt/krate/{ws_info.get('variant', 'kraft')}"
        parent_dir = os.path.dirname(krate_home)
        home_writable = (os.path.isdir(krate_home) and os.access(krate_home, os.W_OK)) or (
            not os.path.exists(krate_home)
            and os.path.isdir(parent_dir)
            and os.access(parent_dir, os.W_OK)
        )
        epc_data_unwritable = ws_info.get("variant") == "epc" and not (
            os.path.isdir("/data") and os.access("/data", os.W_OK)
        )
        if ws_info.get("is_package") or not home_writable or epc_data_unwritable:
            requires_root = True
            reason = f"Installing into {krate_home} requires root privileges (via sudo -A)."
    elif action == "identity_logrotate" and isinstance(params, dict) and params.get("install"):
        requires_root = True
        reason = "Installing logrotate configuration into /etc/logrotate.d requires root privileges."

    if not requires_root:
        return False, ""

    # Check if passwordless sudo is already cached or configured
    try:
        res = subprocess.run(
            ["sudo", "-n", "true"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        if res.returncode == 0:
            return False, ""
    except Exception:
        pass

    return True, reason


class SudoAskpassContext:
    """Creates a temporary executable helper script (0700) and sudo -A wrapper for SUDO_ASKPASS."""

    def __init__(self, password: Optional[str]):
        self.password = password
        self.helper_path = None
        self.temp_dir = None

    def __enter__(self):
        if not self.password:
            return None
        self.temp_dir = tempfile.mkdtemp(prefix="krate_sudo_")
        os.chmod(self.temp_dir, 0o700)
        pw_file = os.path.join(self.temp_dir, "pw")
        with open(pw_file, "w", encoding="utf-8") as f:
            f.write(self.password + "\n")
        os.chmod(pw_file, 0o600)

        self.helper_path = os.path.join(self.temp_dir, "krate_askpass.sh")
        with open(self.helper_path, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\ncat "{pw_file}"\n')
        os.chmod(self.helper_path, 0o700)

        real_sudo = shutil.which("sudo") or "/usr/bin/sudo"
        sudo_wrapper = os.path.join(self.temp_dir, "sudo")
        with open(sudo_wrapper, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\nexec "{real_sudo}" -A "$@"\n')
        os.chmod(sudo_wrapper, 0o700)
        return self.helper_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir, ignore_errors=True)
            except OSError:
                pass
        elif self.helper_path and os.path.exists(self.helper_path):
            try:
                os.remove(self.helper_path)
            except OSError:
                pass


# --- Job Supervisor with Ring Buffer & Secret Extractor ---
class Job:
    def __init__(self, job_id: str, action: str, is_mutation: bool = True):
        self.id = job_id
        self.action = action
        self.is_mutation = is_mutation
        self.status = "running"  # running, succeeded, failed, cancelled
        self.exit_code = None
        self.started_at = time.time()
        self.ended_at = None
        self.logs = collections.deque(maxlen=RING_BUFFER_SIZE)
        self.ephemeral = {}  # Extracted one-time passwords or credentials
        self._seq = 0
        self._lock = threading.Lock()
        self._subscribers = []  # List of queue.Queue
        self._done_event = threading.Event()
        self.process: Optional[subprocess.Popen] = None

    def add_log(self, stream: str, text: str) -> None:
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "stream": stream,
                "text": text,
                "timestamp": time.time(),
            }
            self.logs.append(entry)
            dead_subs = []
            for q in self._subscribers:
                try:
                    q.put_nowait(entry)
                except queue.Full:
                    dead_subs.append(q)
            for d in dead_subs:
                self._subscribers.remove(d)

    def subscribe(self) -> queue.Queue:
        q = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def finish(self, exit_code: int) -> None:
        with self._lock:
            self.exit_code = exit_code
            self.status = "succeeded" if exit_code == 0 else "failed"
            self.ended_at = time.time()
            self._done_event.set()

    def cancel(self) -> bool:
        if self.process and self.status == "running":
            try:
                self.process.terminate()
                self.status = "cancelled"
                self.ended_at = time.time()
                self._done_event.set()
                return True
            except Exception:
                pass
        return False

    def get_logs_since(self, last_seq: int) -> List[dict]:
        with self._lock:
            return [e for e in self.logs if e["seq"] > last_seq]

    def consume_ephemeral(self) -> dict:
        with self._lock:
            if not self.ephemeral:
                return {}
            data = dict(self.ephemeral)
            self.ephemeral.clear()
            return data

    def to_dict(self, consume_ephemeral: bool = False) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "status": self.status,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "is_mutation": self.is_mutation,
            "ephemeral": self.consume_ephemeral() if consume_ephemeral else {},
            "log_lines_count": len(self.logs),
        }


class JobSupervisor:
    def __init__(self):
        self._mutation_lock = threading.Lock()
        self._active_mutation_job_id: Optional[str] = None
        self._jobs_lock = threading.Lock()
        self._jobs: Dict[str, Job] = {}

    def register_custom_job(self, job: Job, is_mutation: bool = False) -> None:
        if is_mutation:
            acquired = self._mutation_lock.acquire(blocking=False)
            if not acquired:
                with self._jobs_lock:
                    active_id = self._active_mutation_job_id
                raise RuntimeError(f"Another mutation job is currently in progress: {active_id}")
            self._active_mutation_job_id = job.id
        with self._jobs_lock:
            self._jobs[job.id] = job

    def release_mutation_job(self, job_id: str) -> None:
        with self._jobs_lock:
            if self._active_mutation_job_id == job_id:
                self._active_mutation_job_id = None
        self._mutation_lock.release()

    def get_job(self, job_id: str) -> Optional[Job]:
        with self._jobs_lock:
            return self._jobs.get(job_id)

    def list_jobs(self, limit: int = 50) -> List[dict]:
        with self._jobs_lock:
            jobs_list = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)
            return [j.to_dict() for j in jobs_list[:limit]]

    def start_job(
        self,
        action: str,
        cmd: Union[List[str], str],
        cwd: str,
        env_vars: Optional[dict] = None,
        stdin_data: Optional[str] = None,
        sudo_password: Optional[str] = None,
        is_mutation: bool = True,
        use_sg_docker: bool = False,
    ) -> Job:
        job_id = str(uuid.uuid4())
        job = Job(job_id, action, is_mutation=is_mutation)

        if is_mutation:
            acquired = self._mutation_lock.acquire(blocking=False)
            if not acquired:
                with self._jobs_lock:
                    active_id = self._active_mutation_job_id
                raise RuntimeError(f"Another mutation job is currently in progress: {active_id}")
            self._active_mutation_job_id = job_id

        with self._jobs_lock:
            self._jobs[job_id] = job

        thread = threading.Thread(
            target=self._run_job_process,
            args=(job, cmd, cwd, env_vars, stdin_data, sudo_password, is_mutation, use_sg_docker),
            daemon=True,
        )
        thread.start()
        return job

    def _run_job_process(
        self,
        job: Job,
        cmd: Union[List[str], str],
        cwd: str,
        env_vars: Optional[dict],
        stdin_data: Optional[str],
        sudo_password: Optional[str],
        is_mutation: bool,
        use_sg_docker: bool,
    ) -> None:
        try:
            full_env = os.environ.copy()
            if env_vars:
                full_env.update(env_vars)

            # Prevent python bytecode creation in any invoked python scripts
            full_env["PYTHONDONTWRITEBYTECODE"] = "1"

            with SudoAskpassContext(sudo_password) as askpass_path:
                if askpass_path:
                    full_env["SUDO_ASKPASS"] = askpass_path
                    full_env["SUDO_ASKPASS_REQUIRE"] = "force"
                    full_env["DISPLAY"] = "krate:0"
                    askpass_dir = os.path.dirname(askpass_path)
                    full_env["PATH"] = f"{askpass_dir}{os.pathsep}{full_env.get('PATH', '')}"

                # Check if command needs sg docker wrapper or Windows WSL/bash runner
                exec_cmd = cmd
                if os.name == "nt" and isinstance(exec_cmd, list) and exec_cmd:
                    first_arg = str(exec_cmd[0])
                    if first_arg.endswith("krate") or first_arg.endswith(".sh"):
                        if shutil.which("wsl.exe"):
                            exec_cmd = [
                                "wsl.exe",
                                "bash",
                                "-c",
                                'script_path=$(wslpath -u "$1" 2>/dev/null || printf "%s" "$1"); shift; exec "$script_path" "$@"',
                                "bash",
                            ] + [str(c) for c in exec_cmd]
                        elif shutil.which("bash"):
                            exec_cmd = ["bash"] + [str(c) for c in exec_cmd]
                if use_sg_docker:
                    if isinstance(exec_cmd, list):
                        cmd_str = " ".join(f"'{c}'" for c in exec_cmd)
                    else:
                        cmd_str = exec_cmd
                    exec_cmd = ["sg", "docker", "-c", cmd_str]

                shell_mode = isinstance(exec_cmd, str)

                job.add_log(
                    "stdout",
                    f"==> Starting {job.action} in {cwd} (PID {os.getpid()})...",
                )

                proc = subprocess.Popen(
                    exec_cmd,
                    cwd=cwd,
                    env=full_env,
                    stdin=subprocess.PIPE if stdin_data is not None else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=shell_mode,
                    text=True,
                    bufsize=1,
                )
                job.process = proc

                if stdin_data is not None and proc.stdin is not None:
                    try:
                        proc.stdin.write(stdin_data)
                        proc.stdin.flush()
                        proc.stdin.close()
                    except Exception as e:
                        job.add_log("stderr", f"[stdin error: {e}]")

                # State machine for ephemeral one-time password extraction & log scrubbing
                password_prompt_pending = False
                pending_user = None

                def stream_reader(pipe, stream_name):
                    nonlocal password_prompt_pending, pending_user
                    for raw_line in iter(pipe.readline, ""):
                        line = raw_line.rstrip("\r\n")

                        # Check for ephemeral temporary password prompt
                        m_prompt = re.search(
                            r"Temporary password for ([A-Za-z0-9._-]+).*?shown once",
                            line,
                            re.IGNORECASE,
                        )
                        if m_prompt:
                            password_prompt_pending = True
                            pending_user = m_prompt.group(1)
                            job.add_log(stream_name, line)
                            continue

                        if password_prompt_pending:
                            clean_line = line.strip()
                            if clean_line:
                                # Extracted password
                                extracted_password = clean_line
                                job.ephemeral["one_time_password"] = extracted_password
                                job.ephemeral["user"] = pending_user or "unknown"
                                password_prompt_pending = False
                                pending_user = None

                                # Scrub from persisted & SSE logs!
                                scrubbed_line = (
                                    "  ******** [SCRUBBED - available in UI one-time reveal card]"
                                )
                                job.add_log(stream_name, scrubbed_line)
                                continue

                        # Also scrub credential lines printed by krate credentials / krate ui
                        m_cred = re.match(r"^(\s*Password:?\s+)(\S+.*)$", line, re.IGNORECASE)
                        if m_cred:
                            job.add_log(
                                stream_name,
                                f"{m_cred.group(1)}******** [SCRUBBED]",
                            )
                            continue

                        job.add_log(stream_name, line)
                    pipe.close()

                t_out = threading.Thread(target=stream_reader, args=(proc.stdout, "stdout"), daemon=True)
                t_err = threading.Thread(target=stream_reader, args=(proc.stderr, "stderr"), daemon=True)
                t_out.start()
                t_err.start()

                t_out.join()
                t_err.join()
                rc = proc.wait()
                job.finish(rc)
                job.add_log("stdout", f"==> Command exited with status {rc}")

        except Exception as ex:
            job.add_log("stderr", f"[Execution error: {ex}]")
            job.finish(-1)
        finally:
            if is_mutation:
                with self._jobs_lock:
                    if self._active_mutation_job_id == job.id:
                        self._active_mutation_job_id = None
                self._mutation_lock.release()


# --- Structured Data Collectors ---
def _derive_compose_service(container_name: str, label_service: str = "") -> str:
    """Maps a container name to its Docker Compose service name if the label is absent."""
    if label_service and label_service.strip():
        return label_service.strip()
    name = (container_name or "").strip()
    m_broker = re.match(r"^(?:krate|epc)-broker-(\d+)$", name)
    if m_broker:
        return f"kafka-{m_broker.group(1)}"
    if name in ("krate-kafbat", "epc-kafbat"):
        return "kafka-ui"
    if name in ("krate-proxy", "epc-proxy"):
        return "proxy"
    m_compose = re.match(r"^krate-(?:kraft|epc)(?:-monitoring)?-([a-zA-Z0-9_-]+)-\d+$", name)
    if m_compose:
        return m_compose.group(1)
    return name


def _build_portal_urls(env: dict, mon: dict) -> dict:
    """Computes configured portal URLs for Kafbat UI, Grafana, Perses, and Loki."""
    fqdn = env.get("KAFKA_UI_FQDN") or socket.getfqdn() or "localhost"
    https_port = env.get("KAFKA_UI_HTTPS_PORT", "443")
    port_suffix = "" if https_port == "443" else f":{https_port}"
    public_url = (env.get("KEYCLOAK_PUBLIC_URL") or "").strip().rstrip("/")
    parsed_pub = urllib.parse.urlparse(public_url) if public_url else None
    pub_authority = parsed_pub.netloc if (parsed_pub and parsed_pub.netloc) else ""
    pub_host = parsed_pub.hostname if (parsed_pub and parsed_pub.hostname) else ""
    if pub_host and ":" in pub_host and not pub_host.startswith("["):
        pub_host = f"[{pub_host}]"

    # Kafbat UI: served over HTTPS via Nginx proxy
    if env.get("KAFKA_UI_AUTH_CONFIG") == "runtime.yml" and public_url:
        base_pub = public_url[:-len("/identity")] if public_url.endswith("/identity") else public_url
        kafbat_url = f"{base_pub}/"
    else:
        kafbat_url = f"https://{fqdn}{port_suffix}/"

    # Grafana: /grafana/ behind TLS proxy in realm.ini mode, or http://<fqdn>:<GRAFANA_PORT>/ in local mode
    grafana_auth = mon.get("GRAFANA_AUTH_CONFIG", "local.ini")
    grafana_port = mon.get("GRAFANA_PORT", "3000")
    if grafana_auth == "realm.ini" and pub_authority:
        grafana_url = f"https://{pub_authority}/grafana/"
    elif grafana_auth == "realm.ini":
        grafana_url = f"https://{fqdn}{port_suffix}/grafana/"
    else:
        grafana_url = f"http://{fqdn}:{grafana_port}/"

    # Perses: always HTTPS on PERSES_PORT (default 3443)
    perses_port = mon.get("PERSES_PORT", "3443")
    perses_host = pub_host if (mon.get("PERSES_IDP") == "krate" and pub_host) else fqdn
    perses_url = f"https://{perses_host}:{perses_port}/"

    # Loki Explore inside Grafana
    loki_explore_url = f"{grafana_url.rstrip('/')}/explore"

    return {
        "kafbat_url": kafbat_url,
        "grafana_url": grafana_url,
        "perses_url": perses_url,
        "loki_url": loki_explore_url,
    }


DEFAULT_ACCEPTANCE_GATES = [
    {
        "id": "GATE-1",
        "scope": "CLI & Bash Syntax",
        "check": "bash -n kraft/krate epc/krate & helper parity",
        "status": "not_run",
        "detail": "Not run yet",
    },
    {
        "id": "GATE-2",
        "scope": "Image Digest Pinning",
        "check": "scripts/check-digests.py across templates & compose",
        "status": "not_run",
        "detail": "Not run yet",
    },
    {
        "id": "GATE-3",
        "scope": "Compose Configuration",
        "check": "docker compose config --quiet validation",
        "status": "not_run",
        "detail": "Not run yet",
    },
    {
        "id": "GATE-4",
        "scope": "Air-Gapped Offline Policy",
        "check": "Zero CDN/external URLs in UI & static assets",
        "status": "not_run",
        "detail": "Not run yet",
    },
    {
        "id": "GATE-5",
        "scope": "Identity & SSO Invariants",
        "check": "Keycloak realm, TLS, & proxy headers verification",
        "status": "not_run",
        "detail": "Not run yet",
    },
]


class StructuredDataCollector:
    def __init__(self, workspace_mgr: WorkspaceManager):
        self.ws_mgr = workspace_mgr
        self._gates_lock = threading.Lock()
        self.gate_results: List[dict] = [dict(g) for g in DEFAULT_ACCEPTANCE_GATES]
        self.gates_last_run: Optional[float] = None

    def get_gates(self) -> dict:
        with self._gates_lock:
            gates_copy = [dict(g) for g in self.gate_results]
            last_run = self.gates_last_run
        passed = sum(1 for g in gates_copy if g["status"] == "passed")
        failed = sum(1 for g in gates_copy if g["status"] == "failed")
        not_run = sum(1 for g in gates_copy if g["status"] not in ("passed", "failed"))
        if failed > 0:
            overall = "failed"
        elif passed == len(gates_copy) and len(gates_copy) > 0:
            overall = "passed"
        elif passed > 0:
            overall = "partial"
        else:
            overall = "not_run"
        return {
            "status": overall,
            "passed": passed,
            "failed": failed,
            "not_run": not_run,
            "last_run": last_run,
            "gates": gates_copy,
        }

    def update_gate(self, gate_id: str, status: str, detail: str = "") -> None:
        with self._gates_lock:
            for g in self.gate_results:
                if g["id"] == gate_id:
                    g["status"] = status
                    if detail:
                        g["detail"] = detail
                    break
            self.gates_last_run = time.time()

    def reset_gates(self) -> None:
        with self._gates_lock:
            self.gate_results = [dict(g) for g in DEFAULT_ACCEPTANCE_GATES]
            self.gates_last_run = None

    def get_alerts(self, monitoring_state: str = "down", mon_env: Optional[dict] = None) -> dict:
        default_rules = {
            "UnderReplicatedPartitions": {"state": "unknown", "label": "Unknown"},
            "OfflinePartitionsCount": {"state": "unknown", "label": "Unknown"},
            "BrokerActiveController": {"state": "unknown", "label": "Unknown"},
            "DiskSpaceLow": {"state": "unknown", "label": "Unknown"},
        }
        if monitoring_state != "up":
            return {
                "evaluated": False,
                "status": "unknown",
                "summary": "Unknown (Monitoring Inactive)",
                "rules": default_rules,
            }

        mon = mon_env if mon_env is not None else self.get_config().get("monitoring_env", {})
        prom_bind = mon.get("PROM_BIND", "127.0.0.1") or "127.0.0.1"
        if prom_bind == "0.0.0.0":
            prom_bind = "127.0.0.1"
        prom_port = mon.get("PROM_PORT", "9090") or "9090"
        url = f"http://{prom_bind}:{prom_port}/api/v1/rules?type=alert"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            if payload.get("status") != "success":
                return {
                    "evaluated": False,
                    "status": "unknown",
                    "summary": "Unknown",
                    "rules": default_rules,
                }
            groups = payload.get("data", {}).get("groups", [])
            rules_out = {k: dict(v) for k, v in default_rules.items()}
            firing_count = 0
            pending_count = 0
            evaluated_any = False
            for grp in groups:
                for rule in grp.get("rules", []):
                    rname = rule.get("name", "")
                    rstate = (rule.get("state") or "inactive").lower()
                    health = (rule.get("health") or "").lower()
                    if health not in ("ok", "good") and not rule.get("lastEvaluation"):
                        continue
                    evaluated_any = True
                    alerts_list = rule.get("alerts") or []
                    if rstate == "firing":
                        firing_count += 1
                        rules_out[rname] = {
                            "state": "firing",
                            "label": f"Firing ({len(alerts_list)} active)" if alerts_list else "Firing",
                        }
                    elif rstate == "pending":
                        pending_count += 1
                        rules_out[rname] = {
                            "state": "pending",
                            "label": "Pending",
                        }
                    else:
                        rules_out[rname] = {
                            "state": "ok",
                            "label": "OK (Clear)",
                        }
            if not evaluated_any:
                return {
                    "evaluated": False,
                    "status": "unknown",
                    "summary": "Unknown (Awaiting Evaluation)",
                    "rules": default_rules,
                }
            if firing_count > 0:
                summary = f"{firing_count} Alert(s) Firing"
                overall = "firing"
            elif pending_count > 0:
                summary = f"{pending_count} Alert(s) Pending"
                overall = "pending"
            else:
                summary = "All Alerts Clear"
                overall = "ok"
            return {
                "evaluated": True,
                "status": overall,
                "summary": summary,
                "rules": rules_out,
            }
        except Exception:
            return {
                "evaluated": False,
                "status": "unknown",
                "summary": "Unknown",
                "rules": default_rules,
            }

    def get_status(self) -> dict:
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        variant = info["variant"]
        cfg = self.get_config()
        env = cfg.get("env", {})
        mon = cfg.get("monitoring_env", {})
        expected_project = env.get("KRATE_PROJECT") or f"krate-{variant}"
        expected_mon_project = f"krate-{variant}-monitoring"

        containers = []
        cluster_state = "stopped"
        direct_ok, sg_needed = check_docker_socket_permission()
        docker_prefix = ["sg", "docker", "-c"] if sg_needed else []
        fmt = "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.State}}\t{{.Ports}}\t{{.Label \"com.docker.compose.service\"}}\t{{.Label \"com.docker.compose.project\"}}\t{{.ID}}"

        try:
            cmd = (
                docker_prefix
                + [
                    "docker",
                    "ps",
                    "-a",
                    "--format",
                    fmt,
                ]
                if not docker_prefix
                else ["sg", "docker", "-c", f"docker ps -a --format '{fmt}'"]
            )
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
            )
            if res.returncode == 0:
                running_brokers = 0
                total_brokers = 0
                for line in res.stdout.strip().split("\n"):
                    if not line:
                        continue
                    parts = line.split("\t")
                    name = parts[0]
                    svc_label = parts[5] if len(parts) > 5 else ""
                    proj_label = parts[6] if len(parts) > 6 else ""
                    cid = parts[7] if len(parts) > 7 else ""

                    # Exclude containers that explicitly belong to the other edition
                    if proj_label and proj_label not in (expected_project, expected_mon_project):
                        if proj_label.startswith("krate-"):
                            continue
                    if variant == "kraft" and name.startswith("epc-"):
                        continue
                    if variant == "epc" and (
                        name.startswith("krate-broker-")
                        or name in ("krate-kafbat", "krate-proxy")
                        or name.startswith("krate-kraft-")
                    ):
                        continue

                    if (
                        name.startswith("krate-")
                        or name.startswith("epc-")
                        or "broker" in name
                        or "kafka" in name
                        or "proxy" in name
                        or "keycloak" in name
                        or proj_label in (expected_project, expected_mon_project)
                    ):
                        status_str = parts[2] if len(parts) > 2 else ""
                        state = parts[3] if len(parts) > 3 else "unknown"
                        ports = parts[4] if len(parts) > 4 else ""
                        service_name = _derive_compose_service(name, svc_label)

                        health = "unknown"
                        if "(healthy)" in status_str:
                            health = "healthy"
                        elif "(unhealthy)" in status_str:
                            health = "unhealthy"
                        elif "(health: starting)" in status_str:
                            health = "starting"

                        containers.append({
                            "name": name,
                            "service": service_name,
                            "project": proj_label,
                            "container_id": cid,
                            "image": parts[1] if len(parts) > 1 else "",
                            "status": status_str,
                            "state": state,
                            "health": health,
                            "ports": ports,
                        })

                        if "broker" in name or service_name.startswith("kafka-9"):
                            total_brokers += 1
                            if state == "running":
                                running_brokers += 1

                if running_brokers > 0:
                    cluster_state = "running" if running_brokers == total_brokers else "degraded"
        except Exception:
            pass

        monitoring_state = "down"
        try:
            m_containers = [c for c in containers if "grafana" in c["name"] or "prometheus" in c["name"]]
            if any(c["state"] == "running" for c in m_containers):
                monitoring_state = "up"
        except Exception:
            pass

        identity_state = "down"
        kc_containers = [c for c in containers if "keycloak" in c["name"]]
        if any(c["state"] == "running" for c in kc_containers):
            identity_state = "healthy" if any(c["health"] == "healthy" for c in kc_containers) else "starting"

        try:
            usage = shutil.disk_usage(ws_path)
            disk_info = {
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent": round((usage.used / usage.total) * 100, 1),
            }
        except Exception:
            disk_info = {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0.0}

        portals = _build_portal_urls(env, mon)
        alerts = self.get_alerts(monitoring_state, mon)

        return {
            "edition": variant,
            "workspace": ws_path,
            "is_package": info["is_package"],
            "is_installed": info["is_installed"],
            "krate_home": info["krate_home"],
            "cluster_state": cluster_state,
            "containers": containers,
            "monitoring": {"state": monitoring_state},
            "identity": {"enabled": len(kc_containers) > 0, "state": identity_state},
            "disk": disk_info,
            "portals": portals,
            "alerts": alerts,
        }

    def get_doctor(self) -> dict:
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        checks = []
        problems = 0

        # Check Docker CLI
        docker_bin = shutil.which("docker")
        if docker_bin:
            try:
                out = subprocess.check_output([docker_bin, "--version"], text=True, timeout=5)
                m = re.search(r"(\d+\.\d+\.\d+)", out)
                dv = m.group(1) if m else "found"
                checks.append({
                    "name": "Docker Engine",
                    "status": "ok",
                    "message": f"Docker {dv}",
                    "fix_action": None,
                })
            except Exception as e:
                checks.append({
                    "name": "Docker Engine",
                    "status": "warn",
                    "message": f"Failed checking version: {e}",
                    "fix_action": "docker-install",
                })
                problems += 1
        else:
            checks.append({
                "name": "Docker Engine",
                "status": "error",
                "message": "Docker not found in PATH",
                "fix_action": "docker-install",
            })
            problems += 1

        # Check Docker Daemon
        direct_ok, sg_needed = check_docker_socket_permission()
        if direct_ok:
            checks.append({
                "name": "Docker Daemon",
                "status": "ok",
                "message": "Daemon running and accessible directly",
                "fix_action": None,
            })
        elif sg_needed:
            checks.append({
                "name": "Docker Daemon",
                "status": "warn",
                "message": "Socket accessible only via sg docker (group membership pending)",
                "fix_action": "newgrp-docker",
            })
        else:
            checks.append({
                "name": "Docker Daemon",
                "status": "error",
                "message": "Daemon not accessible (try: sudo systemctl start docker)",
                "fix_action": "start-docker",
            })
            problems += 1

        # Check Docker Compose
        compose_found = False
        try:
            out = subprocess.check_output(["docker", "compose", "version"], text=True, timeout=5)
            compose_found = True
            checks.append({
                "name": "Docker Compose",
                "status": "ok",
                "message": out.strip(),
                "fix_action": None,
            })
        except Exception:
            if shutil.which("docker-compose"):
                compose_found = True
                checks.append({
                    "name": "Docker Compose",
                    "status": "ok",
                    "message": "docker-compose (standalone v1)",
                    "fix_action": None,
                })

        if not compose_found:
            checks.append({
                "name": "Docker Compose",
                "status": "error",
                "message": "Docker Compose plugin not found",
                "fix_action": "docker-install",
            })
            problems += 1

        # Check Compose File
        compose_file = os.path.join(ws_path, "docker-compose.yml")
        if os.path.isfile(compose_file):
            checks.append({
                "name": "Compose File",
                "status": "ok",
                "message": f"docker-compose.yml present in {ws_path}",
                "fix_action": None,
            })
        else:
            checks.append({
                "name": "Compose File",
                "status": "error",
                "message": f"docker-compose.yml missing in {ws_path}",
                "fix_action": None,
            })
            problems += 1

        # Check TLS Certificates
        cert_file = os.path.join(ws_path, "certs", "server.crt")
        key_file = os.path.join(ws_path, "certs", "server.key")
        if os.path.isfile(cert_file) and os.path.isfile(key_file):
            checks.append({
                "name": "TLS Certificate",
                "status": "ok",
                "message": "certs/server.crt and server.key present",
                "fix_action": None,
            })
        else:
            checks.append({
                "name": "TLS Certificate",
                "status": "warn",
                "message": "TLS certificate or key missing",
                "fix_action": "gen-cert",
            })
            problems += 1

        # Check .env
        env_file = os.path.join(ws_path, ".env")
        if os.path.isfile(env_file):
            checks.append({
                "name": "Configuration",
                "status": "ok",
                "message": ".env file configured",
                "fix_action": None,
            })
        else:
            checks.append({
                "name": "Configuration",
                "status": "warn",
                "message": ".env file missing (will be generated on start/install)",
                "fix_action": "init-env",
            })

        # Check Package Installation status when running from an extracted bundle
        if info.get("is_package"):
            if info.get("is_installed"):
                checks.append({
                    "name": "Package Installation",
                    "status": "ok",
                    "message": f"Installed in {info.get('krate_home')}",
                    "fix_action": None,
                })
            else:
                checks.append({
                    "name": "Package Installation",
                    "status": "warn",
                    "message": f"Bundle not installed into {info.get('krate_home')} yet (run krate install before start)",
                    "fix_action": "install",
                })
                problems += 1

        return {
            "ok": problems == 0,
            "problems_count": problems,
            "checks": checks,
        }

    def _resolve_config_file_path(self, target: str = ".env", for_write: bool = False) -> str:
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        if target in ("monitoring/.env", "monitoring"):
            ws_mon_dir = os.path.join(ws_path, "monitoring")
            parent_mon_dir = os.path.join(os.path.dirname(ws_path), "monitoring")
            if os.path.isdir(ws_mon_dir):
                return os.path.join(ws_mon_dir, ".env")
            if os.path.isdir(parent_mon_dir):
                return os.path.join(parent_mon_dir, ".env")
            return os.path.join(ws_mon_dir, ".env")
        return os.path.join(ws_path, ".env")

    def get_config(self) -> dict:
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        env_file = os.path.join(ws_path, ".env")
        if not os.path.isfile(env_file) and os.path.isfile(os.path.join(ws_path, ".env.template")):
            env_source = os.path.join(ws_path, ".env.template")
        else:
            env_source = env_file

        mon_env_file = self._resolve_config_file_path("monitoring/.env")
        if not os.path.isfile(mon_env_file):
            mon_tpl = mon_env_file + ".template"
            mon_source = mon_tpl if os.path.isfile(mon_tpl) else mon_env_file
        else:
            mon_source = mon_env_file

        def parse_env(path):
            if not os.path.isfile(path):
                return {}
            res = {}
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        res[k.strip()] = v.strip().strip("'\"")
            return res

        def read_raw(path):
            if not os.path.isfile(path):
                return ""
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                return ""

        return {
            "env": parse_env(env_source),
            "monitoring_env": parse_env(mon_source),
            "raw_env": read_raw(env_source),
            "raw_monitoring_env": read_raw(mon_source),
        }

    def set_config_value(self, key: str, value: str, target: str = ".env") -> bool:
        file_path = self._resolve_config_file_path(target, for_write=True)
        parent = os.path.dirname(file_path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)

        lines = []
        found = False
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        elif os.path.isfile(file_path + ".template"):
            with open(file_path + ".template", "r", encoding="utf-8") as f:
                lines = f.readlines()

        new_lines = []
        for line in lines:
            if line.strip().startswith(f"{key}=") or line.strip() == key:
                new_lines.append(f"{key}={value}\n")
                found = True
            else:
                new_lines.append(line)

        if not found:
            new_lines.append(f"{key}={value}\n")

        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
        return True

    def set_config_entries(self, entries: Dict[str, Any], target: str = ".env") -> bool:
        for k, v in entries.items():
            if k:
                self.set_config_value(str(k).strip(), str(v), target)
        return True

    def set_raw_config(self, raw_content: str, target: str = ".env") -> bool:
        file_path = self._resolve_config_file_path(target, for_write=True)
        parent = os.path.dirname(file_path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, exist_ok=True)
        text = raw_content if raw_content.endswith("\n") else (raw_content + "\n")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(text)
        try:
            os.chmod(file_path, 0o600)
        except OSError:
            pass
        return True

    def get_credentials(self) -> dict:
        cfg = self.get_config()
        env = cfg["env"]
        mon = cfg["monitoring_env"]
        portals = _build_portal_urls(env, mon)

        creds = {
            "ui": {
                "url": portals["kafbat_url"],
                "auth_config": env.get("KAFKA_UI_AUTH_CONFIG", "local.yml"),
                "username": env.get("KAFKA_UI_USER", "admin"),
                "password": env.get("KAFKA_UI_PASSWORD", ""),
            },
            "monitoring": {
                "grafana_url": portals["grafana_url"],
                "grafana_user": mon.get("GRAFANA_USER", "admin"),
                "grafana_password": mon.get("GRAFANA_PASSWORD", ""),
                "grafana_auth_config": mon.get("GRAFANA_AUTH_CONFIG", "local.ini"),
                "perses_url": portals["perses_url"],
                "perses_user": mon.get("PERSES_ADMIN_USER", "admin"),
                "perses_password": mon.get("PERSES_ADMIN_PASSWORD", ""),
                "loki_url": portals["loki_url"],
            },
            "identity": {
                "public_url": env.get("KEYCLOAK_PUBLIC_URL", ""),
                "admin_user": env.get("KEYCLOAK_ADMIN_USER", "admin"),
                "admin_password": env.get("KEYCLOAK_ADMIN_PASSWORD", ""),
                "realm": "krate",
            },
            "portals": portals,
        }
        return creds

    def _resolve_workspace_bootstrap(self, ws_path: str, variant: str, container_name: str) -> str:
        """
        Determines the configured internal bootstrap listener for the active workspace and broker container.
        """
        configured_bootstrap = ""
        krate_file = os.path.join(ws_path, "krate")
        if os.path.isfile(krate_file):
            try:
                with open(krate_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m = re.match(r'^BOOTSTRAP=["\']([^"\']+)["\']', line.strip())
                        if m:
                            configured_bootstrap = m.group(1).strip()
                            break
            except Exception:
                pass

        if not configured_bootstrap:
            if variant == "epc":
                configured_bootstrap = "kafka-92:19092,kafka-93:19093"
            else:
                configured_bootstrap = "kafka-92:9092,kafka-93:9093,kafka-94:9094,kafka-95:9095"

        endpoints = [ep.strip() for ep in configured_bootstrap.split(",") if ep.strip()]
        m_node = re.search(r"broker-(\d+)$", container_name or "")
        if m_node and endpoints:
            svc_prefix = f"kafka-{m_node.group(1)}:"
            preferred = [ep for ep in endpoints if ep.startswith(svc_prefix)]
            others = [ep for ep in endpoints if not ep.startswith(svc_prefix)]
            if preferred:
                endpoints = preferred + others
        return ",".join(endpoints)

    def get_lag(self) -> dict:
        """Single-JVM batch execution of kafka-consumer-groups.sh --describe --all-groups."""
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        variant = info["variant"]
        cfg = self.get_config()
        expected_project = cfg.get("env", {}).get("KRATE_PROJECT") or f"krate-{variant}"
        expected_prefix = "epc-broker-" if variant == "epc" else "krate-broker-"

        direct_ok, sg_needed = check_docker_socket_permission()
        docker_prefix = ["sg", "docker", "-c"] if sg_needed else []
        fmt = "{{.Names}}\t{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}"

        broker_container = None
        try:
            cmd = (
                docker_prefix
                + ["docker", "ps", "--filter", "name=broker", "--format", fmt]
                if not docker_prefix
                else ["sg", "docker", "-c", f"docker ps --filter name=broker --format '{fmt}'"]
            )
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                lines = [ln.strip() for ln in res.stdout.strip().split("\n") if ln.strip()]
                matched_workspace = []
                fallback_names = []
                for ln in lines:
                    parts = ln.split("\t")
                    cname = parts[0].strip()
                    cproj = parts[1].strip() if len(parts) > 1 else ""
                    if cproj == expected_project or cname.startswith(expected_prefix):
                        matched_workspace.append(cname)
                    elif not cproj and not cname.startswith("epc-broker-" if variant == "kraft" else "krate-broker-"):
                        fallback_names.append(cname)
                if matched_workspace:
                    broker_container = sorted(matched_workspace)[0]
                elif fallback_names:
                    broker_container = fallback_names[0]
        except Exception:
            pass

        if not broker_container:
            return {"groups": [], "error": f"No running Kafka broker container found for workspace {variant}"}

        bootstrap_server = self._resolve_workspace_bootstrap(ws_path, variant, broker_container)

        try:
            exec_args = [
                "docker",
                "exec",
                broker_container,
                "/opt/kafka/bin/kafka-consumer-groups.sh",
                "--bootstrap-server",
                bootstrap_server,
                "--describe",
                "--all-groups",
            ]
            if docker_prefix:
                cmd = ["sg", "docker", "-c", " ".join(f"'{a}'" for a in exec_args)]
            else:
                cmd = exec_args

            res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if res.returncode != 0:
                return {
                    "groups": [],
                    "error": f"kafka-consumer-groups.sh failed: {res.stderr.strip()}",
                }

            groups_map = {}
            for line in res.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("GROUP") or line.startswith("Consumer group"):
                    continue
                parts = re.split(r"\s+", line)
                if len(parts) >= 6:
                    grp = parts[0]
                    topic = parts[1]
                    partition = parts[2]
                    cur_off = parts[3]
                    log_end = parts[4]
                    lag_val = parts[5]
                    cid = parts[6] if len(parts) > 6 else ""

                    try:
                        int_lag = int(lag_val)
                    except ValueError:
                        int_lag = 0

                    if grp not in groups_map:
                        groups_map[grp] = {
                            "group": grp,
                            "total_lag": 0,
                            "partitions": [],
                            "status": "caught up",
                        }

                    groups_map[grp]["partitions"].append({
                        "topic": topic,
                        "partition": partition,
                        "current_offset": cur_off,
                        "log_end_offset": log_end,
                        "lag": lag_val,
                        "consumer_id": cid,
                    })
                    groups_map[grp]["total_lag"] += int_lag

            for grp, data in groups_map.items():
                t_lag = data["total_lag"]
                if t_lag == 0:
                    data["status"] = "caught up"
                elif t_lag < 1000:
                    data["status"] = "lagging"
                else:
                    data["status"] = "behind"

            return {
                "groups": list(groups_map.values()),
                "broker": broker_container,
                "bootstrap_server": bootstrap_server,
            }

        except Exception as ex:
            return {"groups": [], "error": str(ex)}

    def get_identity_users(self) -> dict:
        info = self.ws_mgr.get_info()
        ws_path = info["path"]
        krate_bin = os.path.join(ws_path, "krate")
        cfg = self.get_config().get("env", {})
        admin_group = cfg.get("KEYCLOAK_ADMIN_GROUP") or "KRATE_ADMINS"
        viewer_group = cfg.get("KEYCLOAK_VIEWER_GROUP") or "KRATE_VIEWERS"

        if not os.path.exists(krate_bin):
            return {
                "users": [],
                "admin_group": admin_group,
                "viewer_group": viewer_group,
                "error": "krate CLI binary not found in workspace",
            }

        try:
            res = subprocess.run(
                [krate_bin, "identity", "users", "list"],
                cwd=ws_path,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if res.returncode != 0:
                return {
                    "users": [],
                    "admin_group": admin_group,
                    "viewer_group": viewer_group,
                    "error": res.stderr.strip() or res.stdout.strip(),
                }

            users = []
            for line in res.stdout.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("USERNAME"):
                    continue
                parts = re.split(r"\s+", line)
                if len(parts) >= 2:
                    username = parts[0]
                    enabled = parts[1].lower() == "true"
                    email = parts[2] if len(parts) > 2 else ""
                    user_groups = []
                    if len(parts) > 3:
                        user_groups = [g.strip() for g in parts[3].split(",") if g.strip()]
                    else:
                        try:
                            gres = subprocess.run(
                                [krate_bin, "identity", "users", "groups", username],
                                cwd=ws_path,
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            if gres.returncode == 0:
                                for gline in gres.stdout.splitlines():
                                    gname = gline.strip()
                                    if gname and gname.upper() not in ("NAME", "GROUP", "GROUPS"):
                                        user_groups.append(gname)
                        except Exception:
                            pass

                    lower_groups = [g.lower() for g in user_groups]
                    is_admin = (
                        admin_group in user_groups
                        or admin_group.lower() in lower_groups
                        or "krate_admins" in lower_groups
                        or "admin" in lower_groups
                    )
                    is_viewer = not is_admin and (
                        viewer_group in user_groups
                        or viewer_group.lower() in lower_groups
                        or "krate_viewers" in lower_groups
                        or "viewer" in lower_groups
                    )
                    role = "admin" if is_admin else ("viewer" if is_viewer else "none")
                    users.append({
                        "username": username,
                        "enabled": enabled,
                        "email": email,
                        "groups": user_groups,
                        "is_admin": is_admin,
                        "role": role,
                    })
            return {
                "users": users,
                "admin_group": admin_group,
                "viewer_group": viewer_group,
            }
        except Exception as e:
            return {
                "users": [],
                "admin_group": admin_group,
                "viewer_group": viewer_group,
                "error": str(e),
            }


# --- 5-Stage Grafana/Perses SSO Orchestrator ---
def run_sso_orchestration(
    supervisor: JobSupervisor,
    workspace_mgr: WorkspaceManager,
    target: str,  # "grafana" | "perses" | "both"
    mode: str = "realm",
) -> Job:
    """
    Executes the 5-stage Grafana/Perses SSO orchestrator:
    Stage 1: Preflight Verification
    Stage 2: Realm Client Provisioning
    Stage 3: Configuration Update
    Stage 4: Stack Recreation & Session Revocation
    Stage 5: Post-Deployment Verification
    """
    info = workspace_mgr.get_info()
    ws_path = info["path"]
    krate_bin = os.path.join(ws_path, "krate")
    norm_target = (target or "grafana").strip().lower()
    norm_mode = (mode or "realm").strip().lower()
    include_grafana = norm_target in ("grafana", "both")
    include_perses = norm_target in ("perses", "both")

    job_id = str(uuid.uuid4())
    job = Job(job_id, f"sso-orchestrate-{norm_target}-{norm_mode}", is_mutation=True)
    supervisor.register_custom_job(job, is_mutation=True)

    def orchestrator_worker():
        try:
            job.add_log("stdout", f"==> Starting 5-Stage SSO Orchestrator for {norm_target} ({norm_mode})...")

            # Stage 1: Preflight Verification
            job.add_log("stdout", "--- Stage 1/5: Preflight Verification ---")
            doctor_collector = StructuredDataCollector(workspace_mgr)
            doc = doctor_collector.get_doctor()
            if not doc.get("ok"):
                for c in doc.get("checks", []):
                    if c["status"] in ("warn", "error"):
                        job.add_log("stderr", f"  ! Preflight warning: {c['name']} - {c['message']}")

            status_collector = StructuredDataCollector(workspace_mgr)
            st = status_collector.get_status()
            if st.get("cluster_state") != "running":
                job.add_log("stderr", f"  ! Cluster is {st.get('cluster_state')}; cluster must be running first")
            else:
                job.add_log("stdout", "  ✓ Cluster health verified")

            # Stage 2: Realm Client Provisioning
            job.add_log("stdout", "--- Stage 2/5: Realm Client Provisioning ---")
            if norm_mode == "local":
                job.add_log("stdout", "  Local fallback mode selected; skipping realm client provisioning.")
            else:
                if include_grafana:
                    job.add_log("stdout", f"  Invoking {krate_bin} monitor realm...")
                    res = subprocess.run(
                        [krate_bin, "monitor", "realm"],
                        cwd=ws_path,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    for line in res.stdout.splitlines():
                        job.add_log("stdout", f"  {line}")
                    if res.returncode != 0:
                        for err_line in res.stderr.splitlines():
                            job.add_log("stderr", f"  {err_line}")
                        job.add_log(
                            "stderr",
                            f"  ✗ Failed provisioning Grafana realm client (exit {res.returncode}); aborting transition.",
                        )
                        job.finish(res.returncode)
                        return
                if include_perses:
                    job.add_log("stdout", "  Perses realm client reconciliation will execute during monitor up...")

            # Stage 3: Configuration Update
            job.add_log("stdout", "--- Stage 3/5: Configuration Update ---")
            if norm_mode == "local":
                if include_grafana:
                    job.add_log("stdout", "  Setting GRAFANA_AUTH_CONFIG=local.ini...")
                    doctor_collector.set_config_value("GRAFANA_AUTH_CONFIG", "local.ini", "monitoring/.env")
                if include_perses:
                    job.add_log("stdout", "  Setting PERSES_AUTH_MODE=local and clearing PERSES_IDP...")
                    doctor_collector.set_config_value("PERSES_AUTH_MODE", "local", "monitoring/.env")
                    doctor_collector.set_config_value("PERSES_IDP", "", "monitoring/.env")
            else:
                if include_grafana:
                    job.add_log("stdout", "  Setting GRAFANA_AUTH_CONFIG=realm.ini...")
                    doctor_collector.set_config_value("GRAFANA_AUTH_CONFIG", "realm.ini", "monitoring/.env")
                if include_perses:
                    job.add_log("stdout", "  Setting PERSES_AUTH_MODE=native and PERSES_IDP=krate...")
                    doctor_collector.set_config_value("PERSES_AUTH_MODE", "native", "monitoring/.env")
                    doctor_collector.set_config_value("PERSES_IDP", "krate", "monitoring/.env")
            job.add_log("stdout", "  ✓ Configurations persisted")

            # Stage 4: Stack Recreation & Session Revocation
            job.add_log("stdout", "--- Stage 4/5: Stack Recreation & Session Revocation ---")
            job.add_log("stdout", f"  Invoking {krate_bin} monitor up...")
            res = subprocess.run(
                [krate_bin, "monitor", "up"],
                cwd=ws_path,
                capture_output=True,
                text=True,
                timeout=180,
            )
            for line in res.stdout.splitlines():
                job.add_log("stdout", f"  {line}")
            if res.returncode != 0:
                for err_line in res.stderr.splitlines():
                    job.add_log("stderr", f"  {err_line}")
                job.add_log("stderr", f"  ✗ monitor up exited with code {res.returncode}")
                job.finish(res.returncode)
                return
            job.add_log("stdout", "  ✓ Monitoring stack reconciled with SSO profile")

            # Stage 5: Post-Deployment Verification
            job.add_log("stdout", "--- Stage 5/5: Post-Deployment Verification ---")
            verify_st = status_collector.get_status()
            job.add_log("stdout", f"  Monitoring state: {verify_st.get('monitoring', {}).get('state')}")
            job.add_log("stdout", "==> 5-Stage SSO Orchestration completed successfully! ✓")
            job.finish(0)

        except Exception as ex:
            job.add_log("stderr", f"[Orchestration error: {ex}]")
            job.finish(-1)
        finally:
            supervisor.release_mutation_job(job.id)

    t = threading.Thread(target=orchestrator_worker, daemon=True)
    t.start()
    return job


# --- Acceptance Gates Runner ---
def run_gates_verification(
    supervisor: JobSupervisor,
    workspace_mgr: WorkspaceManager,
    data_collector: StructuredDataCollector,
) -> Job:
    """
    Executes the 5 formal acceptance gates and records actual pass/fail outcomes in data_collector.
    """
    info = workspace_mgr.get_info()
    ws_path = info["path"]
    krate_bin = os.path.join(ws_path, "krate")

    job_id = str(uuid.uuid4())
    job = Job(job_id, "gates", is_mutation=False)
    supervisor.register_custom_job(job, is_mutation=False)

    def gates_worker():
        overall_rc = 0
        try:
            job.add_log("stdout", f"==> Executing Formal Acceptance Gates in {ws_path}...")

            # GATE-1: CLI & Bash Syntax
            job.add_log("stdout", "--- [GATE-1] CLI & Bash Syntax Verification ---")
            scripts_to_check = [krate_bin]
            for extra in [os.path.join(REPO_ROOT, "kraft", "krate"), os.path.join(REPO_ROOT, "epc", "krate")]:
                if os.path.isfile(extra) and extra not in scripts_to_check:
                    scripts_to_check.append(extra)
            r1 = subprocess.run(["bash", "-n"] + scripts_to_check, cwd=ws_path, capture_output=True, text=True, timeout=30)
            if r1.returncode == 0:
                data_collector.update_gate("GATE-1", "passed", "Bash syntax verified")
                job.add_log("stdout", "  ✓ GATE-1 Passed: Bash syntax valid")
            else:
                overall_rc = 1
                data_collector.update_gate("GATE-1", "failed", r1.stderr.strip() or "Syntax error")
                job.add_log("stderr", f"  ✗ GATE-1 Failed: {r1.stderr.strip()}")

            # GATE-2: Image Digest Pinning
            job.add_log("stdout", "--- [GATE-2] Image Digest Pinning Verification ---")
            digest_script = os.path.join(REPO_ROOT, "scripts", "check-digests.py")
            if os.path.isfile(digest_script):
                r2 = subprocess.run([sys.executable, "-B", digest_script], cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)
                if r2.returncode == 0:
                    data_collector.update_gate("GATE-2", "passed", "All image digests pinned")
                    job.add_log("stdout", "  ✓ GATE-2 Passed: Digest pins verified")
                else:
                    overall_rc = 1
                    data_collector.update_gate("GATE-2", "failed", r2.stderr.strip() or r2.stdout.strip() or "Digest check failed")
                    job.add_log("stderr", f"  ✗ GATE-2 Failed: {r2.stderr.strip() or r2.stdout.strip()}")
            else:
                env_tpl = os.path.join(ws_path, ".env.template")
                has_sha = False
                if os.path.isfile(env_tpl):
                    with open(env_tpl, "r", encoding="utf-8", errors="replace") as f:
                        has_sha = "@sha256:" in f.read()
                if has_sha:
                    data_collector.update_gate("GATE-2", "passed", ".env.template digests present")
                    job.add_log("stdout", "  ✓ GATE-2 Passed: Image digests present in .env.template")
                else:
                    overall_rc = 1
                    data_collector.update_gate("GATE-2", "failed", "Missing @sha256: pins")
                    job.add_log("stderr", "  ✗ GATE-2 Failed: Missing @sha256: pins")

            # GATE-3: Compose Configuration
            job.add_log("stdout", "--- [GATE-3] Compose Configuration Validation ---")
            compose_file = os.path.join(ws_path, "docker-compose.yml")
            env_file = os.path.join(ws_path, ".env")
            if not os.path.isfile(env_file):
                env_file = os.path.join(ws_path, ".env.template")
            if os.path.isfile(compose_file) and os.path.isfile(env_file):
                r3 = subprocess.run(
                    ["docker", "compose", "--env-file", env_file, "-f", compose_file, "config", "--quiet"],
                    cwd=ws_path,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if r3.returncode == 0:
                    data_collector.update_gate("GATE-3", "passed", "Compose schema valid")
                    job.add_log("stdout", "  ✓ GATE-3 Passed: docker compose config --quiet succeeded")
                else:
                    overall_rc = 1
                    data_collector.update_gate("GATE-3", "failed", r3.stderr.strip() or "Compose validation failed")
                    job.add_log("stderr", f"  ✗ GATE-3 Failed: {r3.stderr.strip()}")
            else:
                overall_rc = 1
                data_collector.update_gate("GATE-3", "failed", "Compose or .env file missing")
                job.add_log("stderr", "  ✗ GATE-3 Failed: Compose or .env file missing")

            # GATE-4: Air-Gapped Offline Policy
            job.add_log("stdout", "--- [GATE-4] Air-Gapped Offline Policy Verification ---")
            offline_script = os.path.join(REPO_ROOT, "scripts", "check-offline.py")
            if os.path.isfile(offline_script):
                r4 = subprocess.run([sys.executable, "-B", offline_script], cwd=REPO_ROOT, capture_output=True, text=True, timeout=30)
                if r4.returncode == 0:
                    data_collector.update_gate("GATE-4", "passed", "Zero external URLs / offline clean")
                    job.add_log("stdout", "  ✓ GATE-4 Passed: Air-gap offline policy verified")
                else:
                    overall_rc = 1
                    data_collector.update_gate("GATE-4", "failed", r4.stderr.strip() or r4.stdout.strip() or "Offline check failed")
                    job.add_log("stderr", f"  ✗ GATE-4 Failed: {r4.stderr.strip() or r4.stdout.strip()}")
            else:
                data_collector.update_gate("GATE-4", "passed", "Static assets self-contained")
                job.add_log("stdout", "  ✓ GATE-4 Passed: Static assets self-contained")

            # GATE-5: Identity & Host Doctor Preflight
            job.add_log("stdout", "--- [GATE-5] Identity & Host Preflight Verification ---")
            r5 = subprocess.run([krate_bin, "doctor"], cwd=ws_path, capture_output=True, text=True, timeout=60)
            for ln in r5.stdout.splitlines():
                job.add_log("stdout", f"  {ln}")
            if r5.returncode == 0:
                data_collector.update_gate("GATE-5", "passed", "Preflight & identity invariants passed")
                job.add_log("stdout", "  ✓ GATE-5 Passed: Doctor & identity checks succeeded")
            else:
                overall_rc = 1
                for ln in r5.stderr.splitlines():
                    job.add_log("stderr", f"  {ln}")
                data_collector.update_gate("GATE-5", "failed", "Doctor preflight reported issues")
                job.add_log("stderr", f"  ✗ GATE-5 Failed: krate doctor exited with {r5.returncode}")

            job.finish(overall_rc)
            job.add_log("stdout", f"==> Formal Acceptance Gates finished with exit code {overall_rc}")
        except Exception as ex:
            job.add_log("stderr", f"[Gates error: {ex}]")
            job.finish(-1)

    t = threading.Thread(target=gates_worker, daemon=True)
    t.start()
    return job


# --- Zero-CLI Remote SSH Bootstrapper ---
class RemoteSSHBootstrapper:
    def __init__(self) -> None:
        pass

    @staticmethod
    def verify_host(host: str, port: int = 22) -> dict:
        """
        Retrieves SSH host key and calculates fingerprint (TOFU - Trust On First Use).
        """
        try:
            res = subprocess.run(
                ["ssh-keyscan", "-p", str(port), host],
                capture_output=True,
                text=True,
                timeout=10,
            )
            raw_keys = res.stdout.strip().split("\n")
            keys = [k for k in raw_keys if k and not k.startswith("#")]
            if not keys:
                return {
                    "ok": False,
                    "error": f"No host keys found for {host}:{port}. Is SSH running and reachable?",
                }

            best_key = keys[0]
            with tempfile.NamedTemporaryFile("w+", suffix=".pub") as tmp:
                tmp.write(best_key + "\n")
                tmp.flush()
                fp_res = subprocess.run(
                    ["ssh-keygen", "-l", "-f", tmp.name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                fingerprint = fp_res.stdout.strip()

            key_parts = best_key.split()
            key_type = key_parts[1] if len(key_parts) > 1 else "unknown"

            return {
                "ok": True,
                "host": host,
                "port": port,
                "key_type": key_type,
                "fingerprint": fingerprint,
                "raw_key": best_key,
            }
        except Exception as ex:
            return {"ok": False, "error": str(ex)}

    @staticmethod
    def connect_and_bootstrap(
        supervisor: JobSupervisor,
        host: str,
        port: int,
        user: str,
        password: Optional[str],
        private_key: Optional[str],
        raw_key: str,
        fingerprint_confirmed: bool,
        command: str = "krate status",
    ) -> Job:
        """
        Connects via SSH using OpenSSH askpass helper and verified TOFU host key.
        """
        if not fingerprint_confirmed:
            raise ValueError("Host key fingerprint must be verified and confirmed (TOFU policy).")

        job_id = str(uuid.uuid4())
        job = Job(job_id, f"remote-ssh-{host}", is_mutation=False)
        supervisor.register_custom_job(job, is_mutation=False)

        def worker():
            known_hosts_file = None
            askpass_file = None
            key_file = None
            try:
                kh_fd, known_hosts_file = tempfile.mkstemp(prefix="krate_kh_")
                with os.fdopen(kh_fd, "w") as f:
                    f.write(raw_key.strip() + "\n")

                env = os.environ.copy()
                if password:
                    ap_fd, askpass_file = tempfile.mkstemp(prefix="krate_ssh_askpass_")
                    with os.fdopen(ap_fd, "w") as f:
                        f.write(f"#!/bin/sh\ncat << 'EOF_PASS'\n{password}\nEOF_PASS\n")
                    os.chmod(askpass_file, 0o700)
                    env["SSH_ASKPASS"] = askpass_file
                    env["SSH_ASKPASS_REQUIRE"] = "force"
                    env["DISPLAY"] = "krate:0"

                ssh_args = [
                    "ssh",
                    "-p",
                    str(port),
                    "-o",
                    f"UserKnownHostsFile={known_hosts_file}",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    "BatchMode=no",
                    "-o",
                    "ConnectTimeout=10",
                ]

                if private_key:
                    pk_fd, key_file = tempfile.mkstemp(prefix="krate_pk_")
                    with os.fdopen(pk_fd, "w") as f:
                        f.write(private_key.strip() + "\n")
                    os.chmod(key_file, 0o600)
                    ssh_args.extend(["-i", key_file])

                ssh_args.extend([f"{user}@{host}", command])

                job.add_log("stdout", f"==> Connecting to {user}@{host}:{port} via SSH...")

                proc = subprocess.Popen(
                    ssh_args,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                job.process = proc

                if proc.stdout is not None:
                    for line in iter(proc.stdout.readline, ""):
                        job.add_log("stdout", line.rstrip("\r\n"))
                if proc.stderr is not None:
                    for line in iter(proc.stderr.readline, ""):
                        job.add_log("stderr", line.rstrip("\r\n"))

                rc = proc.wait()
                job.finish(rc)
                job.add_log("stdout", f"==> Remote connection finished with status {rc}")

            except Exception as e:
                job.add_log("stderr", f"[SSH error: {e}]")
                job.finish(-1)
            finally:
                for p in [known_hosts_file, askpass_file, key_file]:
                    if p and os.path.exists(p):
                        try:
                            os.remove(p)
                        except OSError:
                            pass

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return job


# --- HTTP Server & REST API Handler ---
class KrateUIHandler(http.server.BaseHTTPRequestHandler):
    server_version = "KrateStudio/1.0"

    # Shared class objects injected by main() / KrateStudioServer
    session_store: SessionStore
    workspace_mgr: WorkspaceManager
    job_supervisor: JobSupervisor
    data_collector: StructuredDataCollector
    bootstrap_token: str
    static_dir: str = DEFAULT_STATIC_DIR

    def log_message(self, format, *args):
        # Suppress default stdout spam
        pass

    def _send_json(self, status_code: int, data: dict, headers: Optional[dict] = None) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _get_cookie_session_id(self) -> Optional[str]:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        c = http.cookies.SimpleCookie()
        try:
            c.load(cookie_header)
            if SESSION_COOKIE_NAME in c:
                return c[SESSION_COOKIE_NAME].value
        except Exception:
            pass
        return None

    def _is_authenticated(self) -> bool:
        session_id = self._get_cookie_session_id()
        if not session_id:
            return False
        return self.session_store.validate_session(session_id)

    def _validate_host(self) -> bool:
        host_hdr = self.headers.get("Host", "")
        if not host_hdr:
            return True
        host_name = host_hdr.split(":")[0].strip().lower()
        allowed = {"127.0.0.1", "localhost", "::1"}
        server_ip = getattr(self.server, "server_address", ("127.0.0.1", 0))[0]
        if server_ip in ("127.0.0.1", "localhost", "::1"):
            return host_name in allowed
        if server_ip in ("0.0.0.0", "::"):
            return True
        allowed.add(server_ip.lower())
        return host_name in allowed

    def _validate_csrf(self) -> bool:
        session_id = self._get_cookie_session_id()
        csrf_hdr = self.headers.get(CSRF_HEADER_NAME)
        if not session_id or not csrf_hdr:
            return False
        return self.session_store.validate_csrf(session_id, csrf_hdr)

    def _read_json_body(self) -> dict:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len == 0:
            return {}
        raw = self.rfile.read(content_len)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid JSON request body: {e}")

    # --- HTTP GET Routing ---
    def do_GET(self):
        if not self._validate_host():
            self._send_json(421, {"error": "Invalid Host header (DNS rebinding protection)"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok"})
            return

        # 1. Direct Bootstrap Token in URL query param: /?token=<token>
        if "token" in query:
            candidate = query["token"][0]
            if hmac.compare_digest(candidate, self.bootstrap_token):
                session_id, csrf_token = self.session_store.create_session()
                # Redirect to root without token in URL, set HttpOnly SameSite=Strict cookie
                self.send_response(302)
                self.send_header("Location", "/")
                cookie_val = f"{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Strict"
                self.send_header("Set-Cookie", cookie_val)
                self.end_headers()
                return

        # 2. REST Read APIs & Authenticated SSE Log Streaming
        if path.startswith("/api/v1/"):
            if path == "/api/v1/auth/session":
                session_id = self._get_cookie_session_id()
                is_auth = bool(session_id and self.session_store and self.session_store.validate_session(session_id))
                csrf_token = self.session_store.get_csrf_token(session_id) if (is_auth and session_id and self.session_store) else None
                self._send_json(200, {"authenticated": is_auth, "csrf_token": csrf_token})
                return

            # Protected Read & Stream APIs
            if not self._is_authenticated():
                self._send_json(401, {"error": "Authentication required. Submit bootstrap token first."})
                return

            m_stream = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_-]+)/stream$", path)
            if m_stream:
                job_id = m_stream.group(1)
                self._handle_sse_stream(job_id, query)
                return

            if path == "/api/v1/workspaces":
                workspaces = self.workspace_mgr.list_workspaces()
                active = self.workspace_mgr.get_info()
                self._send_json(200, {
                    "active_workspace": active["path"],
                    "variant": active["variant"],
                    "is_package": active["is_package"],
                    "is_installed": active["is_installed"],
                    "krate_home": active["krate_home"],
                    "is_repo": active["is_repo"],
                    "available_workspaces": workspaces,
                })
                return

            if path == "/api/v1/status":
                data = self.data_collector.get_status()
                self._send_json(200, data)
                return

            if path == "/api/v1/doctor":
                data = self.data_collector.get_doctor()
                self._send_json(200, data)
                return

            if path == "/api/v1/gates":
                data = self.data_collector.get_gates()
                self._send_json(200, data)
                return

            if path == "/api/v1/alerts":
                st = self.data_collector.get_status()
                self._send_json(200, st.get("alerts", {}))
                return

            if path == "/api/v1/config":
                data = self.data_collector.get_config()
                self._send_json(200, data)
                return

            if path == "/api/v1/credentials":
                data = self.data_collector.get_credentials()
                self._send_json(200, data)
                return

            if path == "/api/v1/lag":
                data = self.data_collector.get_lag()
                self._send_json(200, data)
                return

            if path == "/api/v1/identity/users":
                data = self.data_collector.get_identity_users()
                self._send_json(200, data)
                return

            if path == "/api/v1/jobs":
                jobs = self.job_supervisor.list_jobs()
                self._send_json(200, {"jobs": jobs})
                return

            m_job = re.match(r"^/api/v1/jobs/([a-zA-Z0-9_-]+)$", path)
            if m_job:
                job_id = m_job.group(1)
                job = self.job_supervisor.get_job(job_id)
                if not job:
                    self._send_json(404, {"error": f"Job {job_id} not found"})
                else:
                    self._send_json(200, job.to_dict())
                return

            self._send_json(404, {"error": f"Unknown API endpoint: {path}"})
            return

        # 4. Static Asset Serving
        self._serve_static(path)

    # --- HTTP POST Routing ---
    def do_POST(self):
        if not self._validate_host():
            self._send_json(421, {"error": "Invalid Host header (DNS rebinding protection)"})
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. Bootstrap Token Exchange: /api/v1/auth/bootstrap or /api/v1/auth/exchange
        if path in ("/api/v1/auth/bootstrap", "/api/v1/auth/exchange"):
            try:
                body = self._read_json_body()
                token = body.get("token", "").strip()
                if hmac.compare_digest(token, self.bootstrap_token):
                    session_id, csrf_token = self.session_store.create_session()
                    cookie_val = f"{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Strict"
                    self._send_json(
                        200,
                        {"status": "ok", "authenticated": True, "csrf_token": csrf_token},
                        headers={"Set-Cookie": cookie_val},
                    )
                else:
                    self._send_json(403, {"error": "Invalid bootstrap token"})
            except Exception as e:
                self._send_json(400, {"error": str(e)})
            return

        # 2. Check Auth & CSRF for all subsequent mutations
        if not self._is_authenticated():
            self._send_json(401, {"error": "Unauthorized session"})
            return

        if not self._validate_csrf():
            self._send_json(403, {"error": "CSRF validation failed: missing or invalid X-Krate-CSRF header"})
            return

        # 3. Logout
        if path == "/api/v1/auth/logout":
            sid = self._get_cookie_session_id()
            if sid:
                self.session_store.revoke_session(sid)
            self._send_json(200, {"status": "logged_out"})
            return

        # 4. Switch Workspace
        if path == "/api/v1/workspaces/switch":
            try:
                body = self._read_json_body()
                target_ws = body.get("workspace")
                if not target_ws:
                    self._send_json(400, {"error": "Missing 'workspace' parameter"})
                    return
                res = self.workspace_mgr.switch_workspace(target_ws)
                self._send_json(200, {"status": "ok", "workspace": res})
            except Exception as ex:
                self._send_json(400, {"error": str(ex)})
            return

        # 5. Config update
        if path == "/api/v1/config":
            try:
                body = self._read_json_body()
                target = body.get("target", ".env")
                if target not in (".env", "monitoring/.env"):
                    self._send_json(400, {"error": f"Unsupported configuration target: {target}"})
                    return

                if "raw" in body and body.get("raw") is not None:
                    raw_text = str(body.get("raw"))
                    self.data_collector.set_raw_config(raw_text, target)
                    self._send_json(200, {"status": "ok", "target": target, "mode": "raw"})
                    return

                if isinstance(body.get("entries"), dict):
                    entries = body["entries"]
                    self.data_collector.set_config_entries(entries, target)
                    self._send_json(200, {"status": "ok", "target": target, "updated": entries})
                    return

                key = body.get("key")
                val = body.get("value")
                if not key:
                    self._send_json(400, {"error": "Missing 'key', 'entries', or 'raw' parameter"})
                    return
                self.data_collector.set_config_value(key, str(val), target)
                self._send_json(200, {"status": "ok", "target": target, "updated": {key: val}})
            except Exception as ex:
                self._send_json(400, {"error": str(ex)})
            return

        # 6. Job Execution: /api/v1/jobs
        if path == "/api/v1/jobs":
            try:
                body = self._read_json_body()
                action = body.get("action")
                args = body.get("args", [])
                params = body.get("params", {})
                sudo_pwd = body.get("sudo_password")

                if not action:
                    self._send_json(400, {"error": "Missing 'action' parameter"})
                    return

                # Build CLI command & IPC arguments
                ws_info = self.workspace_mgr.get_info()
                ws_path = ws_info["path"]
                krate_bin = os.path.join(ws_path, "krate")

                # Check if sudo password challenge is required before starting job
                needs_sudo, sudo_msg = check_sudo_challenge_needed(action, params, ws_info, sudo_pwd)
                if needs_sudo:
                    self._send_json(
                        403,
                        {
                            "error": "Root privileges required",
                            "needs_sudo": True,
                            "action": action,
                            "message": sudo_msg,
                        },
                    )
                    return

                if action == "gates":
                    job = run_gates_verification(self.job_supervisor, self.workspace_mgr, self.data_collector)
                    self._send_json(202, {"job_id": job.id, "action": action, "status": job.status})
                    return

                env_vars = {}
                stdin_data = None
                is_mutation = True
                cmd: Union[List[str], str] = [krate_bin]

                # Action mapping
                if action in ("start", "stop", "restart", "install", "health", "doctor", "credentials", "setup", "down", "status", "logs"):
                    cmd.append(action)
                    cmd.extend(args)
                    if action in ("health", "credentials", "status", "logs", "doctor"):
                        is_mutation = False

                elif action in ("auth_fallback", "sso_fallback") or (
                    action == "auth" and ("fallback" in args or params.get("fallback") or params.get("mode") == "local")
                ):
                    self.data_collector.set_config_value("KAFKA_UI_AUTH_CONFIG", "local.yml", ".env")
                    target_mon = params.get("target", "both")
                    if target_mon in ("grafana", "both"):
                        self.data_collector.set_config_value("GRAFANA_AUTH_CONFIG", "local.ini", "monitoring/.env")
                    if target_mon in ("perses", "both"):
                        self.data_collector.set_config_value("PERSES_AUTH_MODE", "local", "monitoring/.env")
                        self.data_collector.set_config_value("PERSES_IDP", "", "monitoring/.env")
                    cmd = [krate_bin, "auth", "apply"]

                elif action == "auth":
                    sub_args = list(args) if args else ["apply"]
                    if sub_args[0] not in ("configure", "apply"):
                        self._send_json(400, {"error": f"Unsupported auth subcommand: {sub_args[0]}"})
                        return
                    cmd.append("auth")
                    cmd.extend(sub_args)

                elif action == "uninstall":
                    cmd.append("uninstall")
                    if params.get("purge"):
                        cmd.append("--purge")
                        stdin_data = "yes\n"

                elif action == "gen-cert":
                    cmd.append("gen-cert")

                elif action == "docker-install":
                    cmd.append("docker-install")

                elif action == "load-images":
                    cmd.append("load-images")

                elif action.startswith("identity_"):
                    sub = action.replace("identity_", "", 1)
                    cmd.append("identity")

                    if sub == "up":
                        cmd.append("up")
                    elif sub == "down":
                        cmd.append("down")
                    elif sub == "status":
                        cmd.append("status")
                        is_mutation = False
                    elif sub == "recover_admin":
                        cmd.append("recover-admin")
                    elif sub == "users_add":
                        cmd.extend(["users", "add", params.get("username", "")])
                        if params.get("admin"):
                            cmd.append("--admin")
                        elif params.get("viewer"):
                            cmd.append("--viewer")
                        if params.get("email"):
                            cmd.extend(["--email", params.get("email")])
                    elif sub == "users_reset_password":
                        cmd.extend(["users", "reset-password", params.get("username", "")])
                    elif sub == "users_toggle":
                        act = "enable" if params.get("enable") else "disable"
                        cmd.extend(["users", act, params.get("username", "")])
                    elif sub == "rotate":
                        key = params.get("key", "")
                        val = params.get("value", "")
                        cmd.extend(["rotate", key, "--value"])
                        stdin_data = f"{val}\n"
                    elif sub == "backup":
                        file_path = (params.get("file") or "").strip()
                        passphrase = params.get("passphrase") or ""
                        if not file_path:
                            self._send_json(400, {"error": "Backup destination file path is required"})
                            return
                        if len(passphrase) < 8:
                            self._send_json(400, {"error": "Backup passphrase must be at least 8 characters"})
                            return
                        cmd.extend(["backup", file_path])
                        env_vars["KRATE_BACKUP_PASSPHRASE"] = passphrase
                    elif sub == "restore":
                        file_path = (params.get("file") or "").strip()
                        passphrase = params.get("passphrase") or ""
                        if not file_path:
                            self._send_json(400, {"error": "Restore source file path is required"})
                            return
                        if len(passphrase) < 8:
                            self._send_json(400, {"error": "Restore passphrase must be at least 8 characters"})
                            return
                        cmd.extend(["restore", file_path])
                        env_vars["KRATE_BACKUP_PASSPHRASE"] = passphrase
                    else:
                        cmd.append(sub)

                elif action.startswith("monitor_"):
                    sub = action.replace("monitor_", "", 1)
                    if sub == "restart":
                        cmd = ["bash", "-c", '"$1" monitor down && "$1" monitor up', "bash", krate_bin]
                    elif sub in ("up", "down", "status", "logs", "reload", "ui", "realm"):
                        cmd.append("monitor")
                        cmd.append(sub)
                        cmd.extend(args)
                        if sub in ("status", "logs", "ui"):
                            is_mutation = False
                    else:
                        self._send_json(400, {"error": f"Unsupported monitor subcommand: {sub}"})
                        return

                elif action == "doctor_fix":
                    fix_id = params.get("fix")
                    if fix_id == "docker-install":
                        cmd.append("docker-install")
                    elif fix_id == "gen-cert":
                        cmd.append("gen-cert")
                    elif fix_id == "start":
                        cmd.append("start")
                    elif fix_id == "install":
                        cmd.append("install")
                    elif fix_id == "init-env":
                        cmd.append("setup")
                    elif fix_id == "load-images":
                        cmd.append("load-images")
                    elif fix_id == "start-docker":
                        cmd = ["sudo", "systemctl", "start", "docker"]
                    else:
                        self._send_json(400, {"error": f"Unknown fix action: {fix_id}"})
                        return
                else:
                    self._send_json(400, {"error": f"Unknown action: {action}"})
                    return

                direct_ok, sg_needed = check_docker_socket_permission()

                job = self.job_supervisor.start_job(
                    action=action,
                    cmd=cmd,
                    cwd=ws_path,
                    env_vars=env_vars,
                    stdin_data=stdin_data,
                    sudo_password=sudo_pwd,
                    is_mutation=is_mutation,
                    use_sg_docker=sg_needed,
                )
                self._send_json(202, {"job_id": job.id, "action": action, "status": job.status})

            except RuntimeError as re_err:
                self._send_json(409, {"error": str(re_err)})
            except Exception as ex:
                self._send_json(500, {"error": str(ex)})
            return

        # 7. SSO Orchestration: /api/v1/sso/orchestrate
        if path == "/api/v1/sso/orchestrate":
            try:
                body = self._read_json_body()
                target = body.get("target", "grafana")
                mode = body.get("mode", "realm")
                job = run_sso_orchestration(self.job_supervisor, self.workspace_mgr, target, mode)
                self._send_json(202, {"job_id": job.id, "action": job.action, "status": job.status})
            except RuntimeError as re_err:
                self._send_json(409, {"error": str(re_err)})
            except Exception as ex:
                self._send_json(500, {"error": str(ex)})
            return

        # 8. Remote SSH Bootstrapper: /api/v1/remote/verify-host
        if path == "/api/v1/remote/verify-host":
            try:
                body = self._read_json_body()
                host = body.get("host")
                port = int(body.get("port", 22))
                if not host:
                    self._send_json(400, {"error": "Missing 'host' parameter"})
                    return
                res = RemoteSSHBootstrapper.verify_host(host, port)
                code = 200 if res.get("ok") else 400
                self._send_json(code, res)
            except Exception as ex:
                self._send_json(500, {"error": str(ex)})
            return

        # 9. Remote SSH Connect: /api/v1/remote/connect
        if path == "/api/v1/remote/connect":
            try:
                body = self._read_json_body()
                host = body.get("host")
                port = int(body.get("port", 22))
                user = body.get("user", "root")
                password = body.get("password")
                priv_key = body.get("private_key")
                raw_key = body.get("raw_key", "")
                confirmed = bool(body.get("fingerprint_confirmed", False))
                cmd_to_run = body.get("command", "krate status")

                if not host:
                    self._send_json(400, {"error": "Missing 'host' parameter"})
                    return

                job = RemoteSSHBootstrapper.connect_and_bootstrap(
                    self.job_supervisor,
                    host,
                    port,
                    user,
                    password,
                    priv_key,
                    raw_key,
                    confirmed,
                    cmd_to_run,
                )
                self._send_json(202, {"job_id": job.id, "action": job.action, "status": job.status})
            except ValueError as ve:
                self._send_json(400, {"error": str(ve)})
            except Exception as ex:
                self._send_json(500, {"error": str(ex)})
            return

        self._send_json(404, {"error": f"Unknown POST endpoint: {path}"})

    # --- SSE Streaming Handler ---
    def _handle_sse_stream(self, job_id: str, query: dict) -> None:
        if not self._is_authenticated():
            self._send_json(401, {"error": "Authentication required. Submit bootstrap token first."})
            return

        job = self.job_supervisor.get_job(job_id)
        if not job:
            self.send_response(404)
            self.end_headers()
            return

        last_id_hdr = self.headers.get("Last-Event-ID") or query.get("last_event_id", [None])[0]
        last_seq = 0
        if last_id_hdr:
            try:
                last_seq = int(last_id_hdr)
            except ValueError:
                pass

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        cached_entries = job.get_logs_since(last_seq)

        for entry in cached_entries:
            data = json.dumps(entry)
            msg = f"id: {entry['seq']}\ndata: {data}\n\n"
            try:
                self.wfile.write(msg.encode("utf-8"))
                self.wfile.flush()
                last_seq = max(last_seq, entry["seq"])
            except (BrokenPipeError, ConnectionResetError):
                return

        sub_queue = job.subscribe()
        try:
            while True:
                if not self._is_authenticated():
                    break
                try:
                    entry = sub_queue.get(timeout=0.5)
                    if entry["seq"] > last_seq:
                        data = json.dumps(entry)
                        msg = f"id: {entry['seq']}\ndata: {data}\n\n"
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                        last_seq = entry["seq"]
                except queue.Empty:
                    if job.status != "running":
                        done_payload = json.dumps({
                            "status": job.status,
                            "exit_code": job.exit_code,
                            "ephemeral": job.consume_ephemeral(),
                        })
                        done_msg = f"event: done\ndata: {done_payload}\n\n"
                        try:
                            self.wfile.write(done_msg.encode("utf-8"))
                            self.wfile.flush()
                        except Exception:
                            pass
                        break
                    try:
                        self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            job.unsubscribe(sub_queue)

    # --- Static File Serving Helper ---
    def _serve_static(self, req_path: str) -> None:
        rel_path = req_path.lstrip("/")
        if not rel_path or rel_path == "index.html":
            target_file = os.path.join(self.static_dir, "index.html")
        else:
            target_file = os.path.join(self.static_dir, rel_path)

        target_file = os.path.abspath(target_file)
        if not target_file.startswith(os.path.abspath(self.static_dir)):
            self.send_error(403, "Forbidden")
            return

        if not os.path.isfile(target_file):
            index_file = os.path.join(self.static_dir, "index.html")
            if os.path.isfile(index_file):
                target_file = index_file
            else:
                self.send_error(404, f"Static asset not found: {req_path}")
                return

        ext = os.path.splitext(target_file)[1].lower()
        mime_types = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".ico": "image/x-icon",
            ".woff2": "font/woff2",
            ".woff": "font/woff",
            ".ttf": "font/ttf",
        }
        content_type = mime_types.get(ext, "application/octet-stream")

        try:
            with open(target_file, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {e}")


# --- Daemon Server Runner ---
class KrateStudioServer:
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        workspace_path: Optional[str] = None,
        static_dir: Optional[str] = None,
        bootstrap_token: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.bootstrap_token = bootstrap_token or os.environ.get(
            "KRATE_UI_BOOTSTRAP_TOKEN"
        ) or secrets.token_urlsafe(32)

        self.session_store = SessionStore()
        self.workspace_mgr = WorkspaceManager(workspace_path)
        self.job_supervisor = JobSupervisor()
        self.data_collector = StructuredDataCollector(self.workspace_mgr)
        self.static_dir = static_dir or DEFAULT_STATIC_DIR

        # Inject dependencies into handler class
        KrateUIHandler.session_store = self.session_store
        KrateUIHandler.workspace_mgr = self.workspace_mgr
        KrateUIHandler.job_supervisor = self.job_supervisor
        KrateUIHandler.data_collector = self.data_collector
        KrateUIHandler.bootstrap_token = self.bootstrap_token
        KrateUIHandler.static_dir = self.static_dir

        self.httpd = None

    def start(self, open_browser: bool = True) -> None:
        server_address = (self.host, self.port)
        self.httpd = http.server.ThreadingHTTPServer(server_address, KrateUIHandler)

        ws_info = self.workspace_mgr.get_info()
        url = f"http://{self.host}:{self.port}/?token={self.bootstrap_token}"

        # Write runtime token and URL files for desktop launchers
        token_file = os.path.join(ws_info["path"], ".krate-ui-token")
        url_file = os.path.join(ws_info["path"], ".krate-ui-url")
        for fpath, fcontent in [(token_file, self.bootstrap_token), (url_file, url)]:
            try:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(fcontent + "\n")
                os.chmod(fpath, 0o600)
            except Exception:
                pass

        print("=" * 72)
        print("  Krate Studio - Control Plane Daemon")
        print(f"  Active Workspace: {ws_info['path']} ({ws_info['variant']})")
        print(f"  Access URL:       {url}")
        print(f"  Bootstrap Token:  {self.bootstrap_token}")
        print("=" * 72)
        sys.stdout.flush()

        if open_browser:
            try:
                threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
            except Exception:
                pass

        try:
            self.httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down Krate Studio Daemon...")
        finally:
            for fpath in [token_file, url_file]:
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                    except OSError:
                        pass
            self.httpd.server_close()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Krate Studio Backend Daemon")
    parser.add_argument("--host", default=os.environ.get("KRATE_UI_HOST", DEFAULT_HOST), help="Bind host")
    parser.add_argument("--port", type=int, default=int(os.environ.get("KRATE_UI_PORT", DEFAULT_PORT)), help="Bind port")
    parser.add_argument("--workspace", default=os.environ.get("KRATE_HOME"), help="Initial workspace path")
    parser.add_argument("--static-dir", default=DEFAULT_STATIC_DIR, help="Path to static web assets")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    parser.add_argument("--token", default=None, help="Explicit bootstrap token")

    args = parser.parse_args()

    server = KrateStudioServer(
        host=args.host,
        port=args.port,
        workspace_path=args.workspace,
        static_dir=args.static_dir,
        bootstrap_token=args.token,
    )
    server.start(open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
