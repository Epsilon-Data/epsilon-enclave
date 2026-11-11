"""
Execute Service Interface
Abstract interface for handling job execution in the enclave
"""
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional, List, NamedTuple

# What happened to the researcher's script. Signed into the execution record.
OUTCOME_SUCCEEDED = 'succeeded'
OUTCOME_FAILED = 'failed'  # ran and exited non-zero
OUTCOME_TIMED_OUT = 'timed_out'
OUTCOME_INVALID_BUNDLE = 'invalid_bundle'  # never ran: bad archive, no script, rejected script
OUTCOME_OUTPUT_REJECTED = 'output_rejected'  # ran, but its output files broke the limits
OUTCOME_ERROR = 'error'  # the enclave could not run it


class BundleResult(NamedTuple):
    """Result of execute_bundle. ``output`` is the error text unless ``success``."""
    success: bool
    output: str
    files: List[Dict[str, Any]]
    outcome: str
    exit_code: Optional[int]


class IExecuteService(ABC):
    """
    Abstract interface for execution services
    Handles secure execution of scripts and data processing within the enclave
    """

    @abstractmethod
    def execute_script(
        self,
        script_content: str,
        session_id: str,
        execution_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, str]:
        """
        Execute a Python script in a secure environment

        Args:
            script_content: Python script code to execute
            session_id: Session ID for security context
            execution_context: Optional execution context and parameters

        Returns:
            Tuple of (success, output or error_message)
        """
        pass

    @abstractmethod
    def execute_bundle(
        self,
        bundle_data: bytes,
        session_id: str,
        script_path: Optional[str] = None,
        csv_data: Optional[bytes] = None
    ) -> BundleResult:
        """
        Execute a script from a decrypted bundle

        Args:
            bundle_data: Decrypted bundle containing script and data
            session_id: Session ID for security context
            script_path: Optional specific script path within bundle
            csv_data: Optional decrypted CSV data to inject into generated/data.csv

        Returns:
            BundleResult(success, execution_output or error_message, output_files,
            outcome, exit_code). output_files is [{"name", "size", "sha256", "type", "content"}] sorted
            by name (path relative to EPSILON_OUTPUT_DIR, "/"-separated),
            collected recursively from EPSILON_OUTPUT_DIR; [] on failure.
        """
        pass

    @abstractmethod
    def execute_with_data(
        self,
        script_content: str,
        data_files: List[str],
        session_id: str,
        output_format: str = "json"
    ) -> Tuple[bool, str]:
        """
        Execute a script with specific data files

        Args:
            script_content: Python script to execute
            data_files: List of data file paths to make available
            session_id: Session ID for security context
            output_format: Format for execution output (json, text, etc.)

        Returns:
            Tuple of (success, formatted_output or error_message)
        """
        pass

    @abstractmethod
    def validate_script(
        self,
        script_content: str
    ) -> Tuple[bool, str]:
        """
        Validate script content for security and syntax

        Args:
            script_content: Python script to validate

        Returns:
            Tuple of (is_valid, error_message or success_message)
        """
        pass

    @abstractmethod
    def setup_execution_environment(
        self,
        session_id: str,
        requirements: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """
        Setup secure execution environment for a session

        Args:
            session_id: Session ID to setup environment for
            requirements: Optional list of Python package requirements

        Returns:
            Tuple of (success, environment_info or error_message)
        """
        pass

    @abstractmethod
    def cleanup_execution_environment(
        self,
        session_id: str
    ) -> bool:
        """
        Clean up execution environment for a session

        Args:
            session_id: Session ID to cleanup

        Returns:
            True if cleanup was successful
        """
        pass

    @abstractmethod
    def get_execution_limits(self) -> Dict[str, Any]:
        """
        Get execution limits and constraints

        Returns:
            Dictionary containing execution limits (memory, time, etc.)
        """
        pass

    @abstractmethod
    def monitor_execution(
        self,
        execution_id: str
    ) -> Dict[str, Any]:
        """
        Monitor ongoing execution status

        Args:
            execution_id: ID of execution to monitor

        Returns:
            Dictionary containing execution status and resource usage
        """
        pass

    @abstractmethod
    def terminate_execution(
        self,
        execution_id: str,
        reason: str = "user_request"
    ) -> bool:
        """
        Terminate a running execution

        Args:
            execution_id: ID of execution to terminate
            reason: Reason for termination

        Returns:
            True if termination was successful
        """
        pass

    @abstractmethod
    def get_execution_logs(
        self,
        execution_id: str,
        log_level: str = "INFO"
    ) -> List[Dict[str, Any]]:
        """
        Get execution logs for debugging

        Args:
            execution_id: ID of execution
            log_level: Minimum log level to retrieve

        Returns:
            List of log entries
        """
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """
        Get list of supported data and output formats

        Returns:
            List of supported format strings
        """
        pass