from openai import OpenAI
from openai import (AuthenticationError, RateLimitError, APIConnectionError)
from typing import Any
import logging

logger = logging.getLogger(__name__)

class BackendAdapter:
    """
    Backend Adapter for communicating with OpenAI-compatible APIs.
    """

    def __init__(self, base_url: str, api_key: str, model: str)-> None:

        logger.info("Initializing BackendAdapter")

        if not base_url:
            raise ValueError("Base URL is required.")

        if not api_key:
            raise ValueError("API Key is required.")

        if not model:
            raise ValueError("Model is required.")
        
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
        )

    def send(self, messages: list[dict], tools: list | None = None)-> dict:
        """
        Public method used by the rest of the project.
        """

        self._validate_messages(messages)
        response = self._send_request(messages, tools)
        result = self._parse_response(response)

        return result

    def _validate_messages(self, messages: list[dict])-> None:
        """
        Validate messages before sending them.
        """

        if not isinstance(messages, list):
            raise TypeError("messages must be a list.")

        if len(messages) == 0:
            raise ValueError("messages cannot be empty.")

        for index, message in enumerate(messages):

            if not isinstance(message, dict):
                raise TypeError(
                    f"Message at index {index} must be a dictionary."
                )

            if "role" not in message:
                raise ValueError(
                    f"Message at index {index} is missing 'role'."
                )

            if "content" not in message:
                raise ValueError(
                    f"Message at index {index} is missing 'content'."
                )

    def _send_request(self, messages: list[dict], tools: list|None = None)-> Any:
        """
        Send the request to the LLM.
        """

        if tools is None:
            tools = []

        try:

            logger.info("Sending request to LLM")

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=tools,
            )

            logger.info("Request completed successfully")

            return response

        except Exception as e:
            logger.exception("Failed to communicate with the LLM")
            raise RuntimeError(f"Unexpected error: {e}") from e

        except RateLimitError:

            logger.exception("Failed to communicate with the LLM")

            raise RuntimeError("Quota exceeded or rate limit reached.")

        except APIConnectionError:

            logger.exception("Failed to communicate with the LLM")

            raise RuntimeError("Failed to connect to the API.")

        except Exception as e:

            logger.exception("Failed to communicate with the LLM")

            raise RuntimeError(f"Unexpected error: {e}")

    def _parse_response(self, response: Any)-> dict:
        """
        Parse the response returned by the LLM.
        """

        choice = response.choices[0]

        message = choice.message

        return {
            "role": message.role,
            "content": message.content,
            "tool_calls": message.tool_calls,
            "finish_reason": choice.finish_reason,
        }