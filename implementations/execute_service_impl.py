"""
Execute Service Implementation
Concrete implementation of IExecuteService interface for secure script execution
"""
import ast
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from typing import Tuple, Dict, Any, Optional, List

from interfaces import IExecuteService
from config import EXECUTION_TIMEOUT, MAX_MEMORY_MB, MAX_OUTPUT_SIZE_MB, MAX_ZIP_ENTRIES, MAX_ZIP_TOTAL_SIZE

logger = logging.getLogger(__name__)


class ExecuteServiceImpl(IExecuteService):
    """
    Concrete implementation of execution service for secure script execution
    """

    def __init__(self, decrypt_service):
        self.decrypt_service = decrypt_service
        self._execution_limits = {
            'max_memory_mb': MAX_MEMORY_MB,
            'max_execution_time_seconds': EXECUTION_TIMEOUT,
            'max_output_size_mb': MAX_OUTPUT_SIZE_MB,
            'allowed_imports': [
                'pandas', 'numpy', 'json', 'csv', 'datetime', 'math', 'os',
                'sys', 'base64', 'hashlib', 're', 'collections', 'itertools',
                'generated'
            ],
            'forbidden_operations': [
                'exec', 'eval', 'compile', '__import__',
                'file', 'input', 'raw_input', 'reload'
            ]
        }
        self._active_executions = {}
        self._executions_lock = threading.Lock()
        self._supported_formats = ['json', 'text', 'csv', 'python_object']

    def execute_script(
        self,
        script_content: str,
        session_id: str,
        execution_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Execute a Python script in a secure environment
        """
        execution_id = f"exec_{session_id}_{int(time.time())}"

        try:
            logger.info(f"[EXECUTE] Starting script execution {execution_id}")

            # Validate script content
            is_valid, validation_msg = self.validate_script(script_content)
            if not is_valid:
                return False, f"Script validation failed: {validation_msg}"

            # Monitor execution start
            self._start_execution_monitoring(execution_id, session_id)

            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name

            try:
                result = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=self._execution_limits['max_execution_time_seconds'],
                    cwd=tempfile.gettempdir()
                )

                # Check output size
                output_size = len(result.stdout) + len(result.stderr)
                max_size = self._execution_limits['max_output_size_mb'] * 1024 * 1024

                if output_size > max_size:
                    return False, f"Output size ({output_size} bytes) exceeds limit ({max_size} bytes)"

                if result.returncode == 0:
                    logger.info(f"[EXECUTE] Script execution {execution_id} successful")
                    return True, result.stdout
                else:
                    logger.error(f"[EXECUTE] Script execution {execution_id} failed: {result.stderr}")
                    return False, f"Script execution failed: {result.stderr}"

            finally:
                try:
                    os.unlink(script_path)
                except OSError as e:
                    logger.debug(f"Could not remove temp script file: {e}")
                self._stop_execution_monitoring(execution_id)

        except subprocess.TimeoutExpired:
            logger.error(f"[EXECUTE] Script execution {execution_id} timed out")
            return False, f"Script execution timed out after {self._execution_limits['max_execution_time_seconds']} seconds"

        except Exception as e:
            logger.error(f"[EXECUTE] Script execution {execution_id} error: {str(e)}")
            return False, f"Script execution error: {str(e)}"

        finally:
            self.cleanup_execution_environment(session_id)

    def execute_bundle(
        self,
        bundle_data: bytes,
        session_id: str,
        script_path: Optional[str] = None,
        csv_data: Optional[bytes] = None
    ) -> Tuple[bool, str]:
        """
        Execute a script from a decrypted bundle

        Args:
            bundle_data: Decrypted ZIP bundle containing the script and dependencies
            session_id: Session identifier for tracking
            script_path: Optional path to script within bundle
            csv_data: Optional decrypted CSV data to inject into generated/data.csv
        """
        execution_id = f"bundle_{session_id}_{int(time.time())}"

        try:
            logger.info(f"[EXECUTE-BUNDLE] Starting bundle execution {execution_id}")
            if csv_data:
                logger.info(f"[EXECUTE-BUNDLE] CSV data provided: {len(csv_data)} bytes")

            # Extract bundle to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Validate and extract zip bundle safely
                t_extract = time.time()
                extraction_error = self._safe_extract_zip(bundle_data, temp_dir)
                if extraction_error:
                    return False, extraction_error
                extract_ms = round((time.time() - t_extract) * 1000, 2)

                logger.info(f"[EXECUTE-BUNDLE] Extracted bundle to {temp_dir} ({extract_ms}ms)")

                # Inject CSV data if provided (Zero Trust: real data replaces dummy data)
                if csv_data:
                    csv_path = os.path.join(temp_dir, 'generated', 'data.csv')
                    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
                    with open(csv_path, 'wb') as f:
                        f.write(csv_data)
                    logger.info(f"[EXECUTE-BUNDLE] Injected CSV data to {csv_path}")

                # Find script file
                target_script = self._find_script(temp_dir, script_path)
                if target_script is None:
                    return False, f"Script not found: {script_path or 'no .py file in bundle'}"

                # Validate script content
                with open(target_script, 'r') as f:
                    script_content = f.read()

                is_valid, validation_msg = self.validate_script(script_content)
                if not is_valid:
                    return False, f"Script validation failed: {validation_msg}"

                # Process any CSV files in the bundle (for cases without injected CSV)
                if not csv_data:
                    success, csv_info = self._process_bundle_csv_files(temp_dir, session_id)
                    if not success:
                        logger.warning(f"[EXECUTE-BUNDLE] CSV processing warning: {csv_info}")

                # Execute script with cwd set to bundle dir (no os.chdir)
                self._start_execution_monitoring(execution_id, session_id)
                try:
                    logger.info(f"[EXECUTE-BUNDLE] Running: {sys.executable} {target_script}")
                    t_run = time.time()
                    result = subprocess.run(
                        [sys.executable, target_script],
                        capture_output=True,
                        text=True,
                        timeout=self._execution_limits['max_execution_time_seconds'],
                        cwd=temp_dir
                    )
                    run_ms = round((time.time() - t_run) * 1000, 2)

                    if result.returncode == 0:
                        logger.info(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} successful ({run_ms}ms)")
                        logger.debug(f"[TIMING] bundle_extract={extract_ms}ms subprocess_run={run_ms}ms")
                        output = result.stdout
                        if result.stderr:
                            output += f"\n--- STDERR ---\n{result.stderr}"
                        return True, output
                    else:
                        logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} failed")
                        logger.error(f"[EXECUTE-BUNDLE] STDERR: {result.stderr}")
                        return False, f"Bundle execution failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
                finally:
                    self._stop_execution_monitoring(execution_id)

        except subprocess.TimeoutExpired:
            logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} timed out")
            return False, f"Bundle execution timed out after {self._execution_limits['max_execution_time_seconds']} seconds"

        except Exception as e:
            logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} error: {str(e)}")
            logger.error(f"[EXECUTE-BUNDLE] Traceback: {traceback.format_exc()}")
            return False, f"Bundle execution error: {str(e)}"

    def execute_with_data(
        self,
        script_content: str,
        data_files: List[str],
        session_id: str,
        output_format: str = "json"
    ) -> Tuple[bool, str]:
        """
        Execute a script with specific data files
        """
        try:
            logger.info(f"[EXECUTE-DATA] Starting script execution with {len(data_files)} data files")

            if output_format not in self._supported_formats:
                return False, f"Unsupported output format: {output_format}"

            with tempfile.TemporaryDirectory() as temp_dir:
                for data_file in data_files:
                    if os.path.exists(data_file):
                        shutil.copy2(data_file, temp_dir)

                script_path = os.path.join(temp_dir, 'script.py')
                with open(script_path, 'w') as f:
                    f.write(script_content)

                result = subprocess.run(
                    [sys.executable, script_path],
                    capture_output=True,
                    text=True,
                    timeout=self._execution_limits['max_execution_time_seconds'],
                    cwd=temp_dir
                )

                if result.returncode == 0:
                    formatted_output = self._format_output(result.stdout, output_format)
                    logger.info(f"[EXECUTE-DATA] Script execution with data successful")
                    return True, formatted_output
                else:
                    logger.error(f"[EXECUTE-DATA] Script execution with data failed: {result.stderr}")
                    return False, f"Script execution failed: {result.stderr}"

        except Exception as e:
            logger.error(f"[EXECUTE-DATA] Script execution with data error: {str(e)}")
            return False, f"Script execution error: {str(e)}"

    def validate_script(
        self,
        script_content: str
    ) -> Tuple[bool, str]:
        """
        Validate script content for security and syntax using AST analysis.
        """
        try:
            try:
                tree = ast.parse(script_content)
            except SyntaxError as e:
                return False, f"Syntax error: {str(e)}"

            allowed = set(self._execution_limits['allowed_imports'])
            forbidden_calls = set(self._execution_limits['forbidden_operations'])

            for node in ast.walk(tree):
                # Check import statements
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top_module = alias.name.split('.')[0]
                        if top_module not in allowed:
                            return False, f"Forbidden import: {alias.name}"

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top_module = node.module.split('.')[0]
                        if top_module not in allowed:
                            return False, f"Forbidden import: {node.module}"

                # Check function calls by name (catches exec(), eval(), compile(), etc.)
                elif isinstance(node, ast.Call):
                    func = node.func
                    if isinstance(func, ast.Name) and func.id in forbidden_calls:
                        return False, f"Forbidden operation: {func.id}()"
                    elif isinstance(func, ast.Attribute) and func.attr in forbidden_calls:
                        return False, f"Forbidden operation: .{func.attr}()"

            return True, "Script validation successful"

        except Exception as e:
            return False, f"Script validation error: {str(e)}"

    def setup_execution_environment(
        self,
        session_id: str,
        requirements: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """
        Setup secure execution environment for a session
        """
        try:
            logger.debug(f"[EXECUTE-SETUP] Setting up execution environment for session {session_id}")

            if requirements:
                allowed_packages = self._execution_limits['allowed_imports']
                for req in requirements:
                    if req not in allowed_packages:
                        return False, f"Package not allowed: {req}"

            return True, "Environment setup successful"

        except Exception as e:
            logger.error(f"[EXECUTE-SETUP] Environment setup failed: {str(e)}")
            return False, f"Environment setup error: {str(e)}"

    def cleanup_execution_environment(
        self,
        session_id: str
    ) -> bool:
        """
        Clean up execution environment for a session
        """
        try:
            with self._executions_lock:
                executions_to_remove = [
                    exec_id for exec_id, exec_info in self._active_executions.items()
                    if exec_info.get('session_id') == session_id
                ]

                for exec_id in executions_to_remove:
                    del self._active_executions[exec_id]

            return True

        except Exception as e:
            logger.error(f"[EXECUTE-CLEANUP] Environment cleanup failed: {str(e)}")
            return False

    def get_execution_limits(self) -> Dict[str, Any]:
        return self._execution_limits.copy()

    def monitor_execution(self, execution_id: str) -> Dict[str, Any]:
        with self._executions_lock:
            if execution_id not in self._active_executions:
                return {'error': f'Execution {execution_id} not found'}

            exec_info = self._active_executions[execution_id]
            runtime = time.time() - exec_info['start_time']

            return {
                'execution_id': execution_id,
                'session_id': exec_info['session_id'],
                'status': exec_info['status'],
                'start_time': exec_info['start_time'],
                'runtime_seconds': runtime,
            }

    def terminate_execution(self, execution_id: str, reason: str = "user_request") -> bool:
        try:
            with self._executions_lock:
                if execution_id in self._active_executions:
                    exec_info = self._active_executions[execution_id]
                    exec_info['status'] = 'terminated'
                    exec_info['termination_reason'] = reason
                    logger.info(f"[EXECUTE-TERMINATE] Execution {execution_id} terminated: {reason}")
                    return True
                else:
                    logger.warning(f"[EXECUTE-TERMINATE] Execution {execution_id} not found")
                    return False
        except Exception as e:
            logger.error(f"[EXECUTE-TERMINATE] Failed to terminate execution {execution_id}: {str(e)}")
            return False

    def get_execution_logs(self, execution_id: str, log_level: str = "INFO") -> List[Dict[str, Any]]:
        with self._executions_lock:
            if execution_id in self._active_executions:
                exec_info = self._active_executions[execution_id]
                return [{
                    'timestamp': exec_info['start_time'],
                    'level': 'INFO',
                    'message': f"Execution {execution_id} started",
                    'session_id': exec_info['session_id']
                }]
        return []

    def get_supported_formats(self) -> List[str]:
        return self._supported_formats.copy()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_extract_zip(self, bundle_data: bytes, dest_dir: str) -> Optional[str]:
        """Safely extract ZIP bundle with path traversal and zip bomb protection.

        Returns None on success, or an error message string on failure.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(bundle_data), 'r') as zf:
                entries = zf.infolist()

                if len(entries) > MAX_ZIP_ENTRIES:
                    return f"ZIP contains too many entries ({len(entries)} > {MAX_ZIP_ENTRIES})"

                total_size = sum(e.file_size for e in entries)
                if total_size > MAX_ZIP_TOTAL_SIZE:
                    return f"ZIP uncompressed size too large ({total_size} > {MAX_ZIP_TOTAL_SIZE})"

                # Check for path traversal
                for entry in entries:
                    target = os.path.realpath(os.path.join(dest_dir, entry.filename))
                    if not target.startswith(os.path.realpath(dest_dir) + os.sep) and target != os.path.realpath(dest_dir):
                        return f"ZIP path traversal detected: {entry.filename}"

                zf.extractall(dest_dir)

        except zipfile.BadZipFile as e:
            return f"Invalid ZIP file: {e}"

        return None

    def _find_script(self, temp_dir: str, script_path: Optional[str]) -> Optional[str]:
        """Locate the script to execute inside the extracted bundle."""
        if script_path:
            target = os.path.join(temp_dir, script_path)
            return target if os.path.exists(target) else None

        for name in ['main.py', 'script.py', 'run.py']:
            target = os.path.join(temp_dir, name)
            if os.path.exists(target):
                logger.info(f"[EXECUTE-BUNDLE] Found script: {name}")
                return target

        py_files = [f for f in os.listdir(temp_dir) if f.endswith('.py')]
        if py_files:
            logger.info(f"[EXECUTE-BUNDLE] Using first .py file: {py_files[0]}")
            return os.path.join(temp_dir, py_files[0])

        return None

    def _process_bundle_csv_files(self, bundle_dir: str, session_id: str) -> Tuple[bool, str]:
        """Process any CSV files already present in the bundle."""
        try:
            csv_files = [f for f in os.listdir(bundle_dir) if f.endswith('.csv')]
            if not csv_files:
                return True, "No CSV files found"

            for csv_file in csv_files:
                logger.info(f"[EXECUTE-CSV] Processing CSV file: {csv_file}")

            return True, f"Processed {len(csv_files)} CSV files"

        except Exception as e:
            return False, f"CSV processing error: {str(e)}"

    def _format_output(self, output: str, format_type: str) -> str:
        """Format output according to requested format."""
        if format_type == 'json':
            try:
                json.loads(output)
                return output
            except (json.JSONDecodeError, ValueError):
                return json.dumps({'output': output})
        return output

    def _start_execution_monitoring(self, execution_id: str, session_id: str):
        with self._executions_lock:
            self._active_executions[execution_id] = {
                'session_id': session_id,
                'start_time': time.time(),
                'status': 'running'
            }

    def _stop_execution_monitoring(self, execution_id: str):
        with self._executions_lock:
            if execution_id in self._active_executions:
                self._active_executions[execution_id]['status'] = 'completed'
                self._active_executions[execution_id]['end_time'] = time.time()
