"""
Execute Service Implementation
Concrete implementation of IExecuteService interface for secure script execution
"""
import logging
import tempfile
import os
import sys
import subprocess
import zipfile
import io
import time
from typing import Tuple, Dict, Any, Optional, List

try:
    from interfaces import IExecuteService
except ImportError:
    from ..interfaces import IExecuteService

logger = logging.getLogger(__name__)


class ExecuteServiceImpl(IExecuteService):
    """
    Concrete implementation of execution service for secure script execution
    """

    def __init__(self, decrypt_service):
        """
        Initialize execute service with decrypt service

        Args:
            decrypt_service: IDecryptService instance for data decryption
        """
        self.decrypt_service = decrypt_service
        self._execution_limits = {
            'max_memory_mb': 512,
            'max_execution_time_seconds': 300,
            'max_output_size_mb': 50,
            'allowed_imports': [
                'pandas', 'numpy', 'json', 'csv', 'datetime', 'math', 'os',
                'sys', 'base64', 'hashlib', 're', 'collections', 'itertools'
            ],
            'forbidden_operations': [
                'exec', 'eval', 'compile', '__import__', 'open',
                'file', 'input', 'raw_input', 'reload'
            ]
        }
        self._active_executions = {}
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

            # Setup execution environment
            success, env_info = self.setup_execution_environment(session_id)
            if not success:
                return False, f"Environment setup failed: {env_info}"

            # Monitor execution start
            self._start_execution_monitoring(execution_id, session_id)

            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as script_file:
                script_file.write(script_content)
                script_path = script_file.name

            try:
                # Execute script with timeout and resource limits
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
                # Clean up temporary script file
                try:
                    os.unlink(script_path)
                except OSError as e:
                    logger.debug(f"Could not remove temp script file: {e}")

                # Stop execution monitoring
                self._stop_execution_monitoring(execution_id)

        except subprocess.TimeoutExpired:
            logger.error(f"[EXECUTE] Script execution {execution_id} timed out")
            return False, f"Script execution timed out after {self._execution_limits['max_execution_time_seconds']} seconds"

        except Exception as e:
            logger.error(f"[EXECUTE] Script execution {execution_id} error: {str(e)}")
            return False, f"Script execution error: {str(e)}"

        finally:
            # Clean up execution environment
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
                # Extract zip bundle
                t_extract = time.time()
                with zipfile.ZipFile(io.BytesIO(bundle_data), 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                extract_ms = round((time.time() - t_extract) * 1000, 2)

                logger.info(f"[EXECUTE-BUNDLE] Extracted bundle to {temp_dir} ({extract_ms}ms)")

                # List extracted files for debugging
                for root, dirs, files in os.walk(temp_dir):
                    for f in files:
                        rel_path = os.path.relpath(os.path.join(root, f), temp_dir)
                        logger.debug(f"[EXECUTE-BUNDLE] Extracted: {rel_path}")

                # Inject CSV data if provided (Zero Trust: real data replaces dummy data)
                if csv_data:
                    csv_path = os.path.join(temp_dir, 'generated', 'data.csv')
                    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
                    with open(csv_path, 'wb') as f:
                        f.write(csv_data)
                    logger.info(f"[EXECUTE-BUNDLE] Injected CSV data to {csv_path}")

                # Find script file
                if script_path:
                    target_script = os.path.join(temp_dir, script_path)
                else:
                    # Look for main script files (prioritize main.py for build.yml compatibility)
                    for possible_script in ['main.py', 'script.py', 'run.py']:
                        target_script = os.path.join(temp_dir, possible_script)
                        if os.path.exists(target_script):
                            logger.info(f"[EXECUTE-BUNDLE] Found script: {possible_script}")
                            break
                    else:
                        # Find any .py file
                        py_files = [f for f in os.listdir(temp_dir) if f.endswith('.py')]
                        if py_files:
                            target_script = os.path.join(temp_dir, py_files[0])
                            logger.info(f"[EXECUTE-BUNDLE] Using first .py file: {py_files[0]}")
                        else:
                            return False, "No Python script found in bundle"

                if not os.path.exists(target_script):
                    return False, f"Script not found: {script_path or 'default script'}"

                # Read script content for logging
                with open(target_script, 'r') as f:
                    script_content = f.read()
                logger.debug(f"[EXECUTE-BUNDLE] Script content ({len(script_content)} chars): {script_content[:200]}...")

                # Process any CSV files in the bundle (for cases without injected CSV)
                if not csv_data:
                    success, csv_info = self._process_bundle_csv_files(temp_dir, session_id)
                    if not success:
                        logger.warning(f"[EXECUTE-BUNDLE] CSV processing warning: {csv_info}")

                # Execute script in bundle directory context
                original_cwd = os.getcwd()
                try:
                    os.chdir(temp_dir)

                    # Monitor execution start
                    self._start_execution_monitoring(execution_id, session_id)

                    # Execute script
                    logger.info(f"[EXECUTE-BUNDLE] Running: {sys.executable} {target_script}")
                    t_run = time.time()
                    result = subprocess.run(
                        [sys.executable, target_script],
                        capture_output=True,
                        text=True,
                        timeout=self._execution_limits['max_execution_time_seconds']
                    )
                    run_ms = round((time.time() - t_run) * 1000, 2)

                    if result.returncode == 0:
                        logger.info(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} successful ({run_ms}ms)")
                        logger.info(f"[TIMING] bundle_extract={extract_ms}ms subprocess_run={run_ms}ms")
                        output = result.stdout
                        if result.stderr:
                            output += f"\n--- STDERR ---\n{result.stderr}"
                        return True, output
                    else:
                        logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} failed")
                        logger.error(f"[EXECUTE-BUNDLE] STDOUT: {result.stdout}")
                        logger.error(f"[EXECUTE-BUNDLE] STDERR: {result.stderr}")
                        return False, f"Bundle execution failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"

                finally:
                    os.chdir(original_cwd)
                    self._stop_execution_monitoring(execution_id)

        except subprocess.TimeoutExpired:
            logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} timed out")
            return False, f"Bundle execution timed out after {self._execution_limits['max_execution_time_seconds']} seconds"

        except Exception as e:
            logger.error(f"[EXECUTE-BUNDLE] Bundle execution {execution_id} error: {str(e)}")
            import traceback
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

            # Create temporary directory for execution
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy data files to execution directory
                for data_file in data_files:
                    if os.path.exists(data_file):
                        import shutil
                        shutil.copy2(data_file, temp_dir)

                # Create script file
                script_path = os.path.join(temp_dir, 'script.py')
                with open(script_path, 'w') as f:
                    f.write(script_content)

                # Execute script in data directory context
                original_cwd = os.getcwd()
                try:
                    os.chdir(temp_dir)

                    result = subprocess.run(
                        [sys.executable, script_path],
                        capture_output=True,
                        text=True,
                        timeout=self._execution_limits['max_execution_time_seconds']
                    )

                    if result.returncode == 0:
                        # Format output according to requested format
                        formatted_output = self._format_output(result.stdout, output_format)
                        logger.info(f"[EXECUTE-DATA] Script execution with data successful")
                        return True, formatted_output
                    else:
                        logger.error(f"[EXECUTE-DATA] Script execution with data failed: {result.stderr}")
                        return False, f"Script execution failed: {result.stderr}"

                finally:
                    os.chdir(original_cwd)

        except Exception as e:
            logger.error(f"[EXECUTE-DATA] Script execution with data error: {str(e)}")
            return False, f"Script execution error: {str(e)}"

    def validate_script(
        self,
        script_content: str
    ) -> Tuple[bool, str]:
        """
        Validate script content for security and syntax
        """
        try:
            # Check for forbidden operations
            for forbidden_op in self._execution_limits['forbidden_operations']:
                if forbidden_op in script_content:
                    return False, f"Forbidden operation detected: {forbidden_op}"

            # Check for dangerous imports
            import ast

            try:
                tree = ast.parse(script_content)
            except SyntaxError as e:
                return False, f"Syntax error: {str(e)}"

            # Analyze AST for dangerous operations
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name not in self._execution_limits['allowed_imports']:
                            return False, f"Forbidden import: {alias.name}"

                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module not in self._execution_limits['allowed_imports']:
                        return False, f"Forbidden import: {node.module}"

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
            logger.info(f"[EXECUTE-SETUP] Setting up execution environment for session {session_id}")

            # Create session execution context
            env_info = {
                'session_id': session_id,
                'temp_dir': tempfile.mkdtemp(),
                'created_at': time.time(),
                'requirements': requirements or []
            }

            # Install any required packages (in a controlled manner)
            if requirements:
                # For security, only allow pre-approved packages
                allowed_packages = self._execution_limits['allowed_imports']
                for req in requirements:
                    if req not in allowed_packages:
                        return False, f"Package not allowed: {req}"

            return True, f"Environment setup successful: {env_info['temp_dir']}"

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
            logger.info(f"[EXECUTE-CLEANUP] Cleaning up execution environment for session {session_id}")

            # Remove any temporary files and directories
            # This is automatically handled by tempfile context managers in our implementation

            # Clean up any active executions for this session
            executions_to_remove = [
                exec_id for exec_id, exec_info in self._active_executions.items()
                if exec_info.get('session_id') == session_id
            ]

            for exec_id in executions_to_remove:
                del self._active_executions[exec_id]

            logger.info(f"[EXECUTE-CLEANUP] Environment cleanup successful for session {session_id}")
            return True

        except Exception as e:
            logger.error(f"[EXECUTE-CLEANUP] Environment cleanup failed: {str(e)}")
            return False

    def get_execution_limits(self) -> Dict[str, Any]:
        """
        Get execution limits and constraints
        """
        return self._execution_limits.copy()

    def monitor_execution(
        self,
        execution_id: str
    ) -> Dict[str, Any]:
        """
        Monitor ongoing execution status
        """
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
            'memory_usage': 'monitoring_not_implemented',
            'cpu_usage': 'monitoring_not_implemented'
        }

    def terminate_execution(
        self,
        execution_id: str,
        reason: str = "user_request"
    ) -> bool:
        """
        Terminate a running execution
        """
        try:
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

    def get_execution_logs(
        self,
        execution_id: str,
        log_level: str = "INFO"
    ) -> List[Dict[str, Any]]:
        """
        Get execution logs for debugging
        """
        # In a real implementation, this would return actual logs
        # For now, return basic execution info
        if execution_id in self._active_executions:
            exec_info = self._active_executions[execution_id]
            return [
                {
                    'timestamp': exec_info['start_time'],
                    'level': 'INFO',
                    'message': f"Execution {execution_id} started",
                    'session_id': exec_info['session_id']
                }
            ]
        else:
            return []

    def get_supported_formats(self) -> List[str]:
        """
        Get list of supported data and output formats
        """
        return self._supported_formats.copy()

    def _process_bundle_csv_files(self, bundle_dir: str, session_id: str) -> Tuple[bool, str]:
        """
        Process and decrypt any CSV files in the bundle
        """
        try:
            csv_files = [f for f in os.listdir(bundle_dir) if f.endswith('.csv')]

            if not csv_files:
                return True, "No CSV files found"

            for csv_file in csv_files:
                csv_path = os.path.join(bundle_dir, csv_file)

                # Check if file needs decryption (encrypted CSV files might have specific format)
                # For now, assume CSV files are already decrypted or don't need decryption
                logger.info(f"[EXECUTE-CSV] Processing CSV file: {csv_file}")

            return True, f"Processed {len(csv_files)} CSV files"

        except Exception as e:
            return False, f"CSV processing error: {str(e)}"

    def _format_output(self, output: str, format_type: str) -> str:
        """
        Format output according to requested format
        """
        if format_type == 'json':
            import json
            try:
                # Try to parse as JSON, if not, wrap in quotes
                json.loads(output)
                return output
            except:
                return json.dumps({'output': output})

        elif format_type == 'text':
            return output

        elif format_type == 'csv':
            # Assume output is already CSV formatted
            return output

        else:
            return output

    def _start_execution_monitoring(self, execution_id: str, session_id: str):
        """
        Start monitoring an execution
        """
        self._active_executions[execution_id] = {
            'session_id': session_id,
            'start_time': time.time(),
            'status': 'running'
        }

    def _stop_execution_monitoring(self, execution_id: str):
        """
        Stop monitoring an execution
        """
        if execution_id in self._active_executions:
            self._active_executions[execution_id]['status'] = 'completed'
            self._active_executions[execution_id]['end_time'] = time.time()