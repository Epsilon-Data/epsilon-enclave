"""
Request Handler Interface
Abstract interface for handling incoming enclave requests
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional


class IRequestHandler(ABC):
    """
    Abstract interface for handling enclave requests
    Defines the contract for processing client requests in a secure manner
    """

    @abstractmethod
    def handle_request(self, request_data: str) -> Dict[str, Any]:
        """
        Process an incoming request and return a response

        Args:
            request_data: JSON string containing the client request

        Returns:
            Dictionary containing the response data

        Response format:
        {
            'success': bool,
            'data': Any,
            'error': Optional[str],
            'session_id': Optional[str],
            'timestamp': str
        }
        """
        pass

    @abstractmethod
    def cleanup_session(self, session_id: str) -> bool:
        """
        Clean up and remove a session

        Args:
            session_id: Session identifier to remove

        Returns:
            True if session was cleaned up successfully
        """
        pass

    @abstractmethod
    def handle_execution(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handle job execution requests

        Args:
            request: Execution request containing encrypted data

        Returns:
            Execution response with results or error
        """
        pass

    @abstractmethod
    def get_health_status(self) -> Dict[str, Any]:
        """
        Get the health status of the request handler

        Returns:
            Dictionary containing health information
        """
        pass