from adapter import BackendAdapter
import pytest
from unittest.mock import Mock, patch
from openai import (AuthenticationError, RateLimitError, APIConnectionError)

@pytest.fixture
def adapter():
    return BackendAdapter(
        base_url="https://test.com",
        api_key="123",
        model="test-model",
    )


def test_validate_messages_success(adapter):
    messages = [
        {
            "role": "user",
            "content": "Hello"
        }
    ]
    adapter._validate_messages(messages)

def test_validate_messages_tool_call_success(adapter):
    
    messages = [
        {
            "role": "assistant",
            "tool_calls": [{"id": "call_123"}]
        }
    ]
    adapter._validate_messages(messages)

def test_validate_messages_not_list(adapter):
    with pytest.raises(TypeError):
        adapter._validate_messages("Hello")

def test_validate_messages_empty(adapter):
    with pytest.raises(ValueError):
        adapter._validate_messages([])

def test_validate_message_not_dict(adapter):
    with pytest.raises(TypeError):
        adapter._validate_messages(["hello"])

def test_validate_message_missing_role(adapter):
    messages = [
        {
            "content": "Hello"
        }
    ]
    with pytest.raises(ValueError):
        adapter._validate_messages(messages)

def test_validate_message_missing_content_and_tools(adapter):
    messages = [
        {
            "role": "user"
        }
    ]
    with pytest.raises(ValueError):
        adapter._validate_messages(messages)

def test_validate_message_tool_missing_id(adapter):
    messages = [
        {
            "role": "tool",
            "content": "Result data"
        }
    ]
    with pytest.raises(ValueError):
        adapter._validate_messages(messages)


def test_parse_response(adapter):
    fake_response = Mock()
    fake_choice = Mock()
    fake_response.choices = [fake_choice]
    
    fake_message = Mock()
    fake_choice.message = fake_message

    fake_message.role = "assistant"
    fake_message.content = "Hello from the AI!"
    fake_message.tool_calls = None

    fake_choice.finish_reason = "stop"

    result = adapter._parse_response(fake_response)

    assert result["role"] == "assistant"
    assert result["content"] == "Hello from the AI!"
    assert result["tool_calls"] is None
    assert result["finish_reason"] == "stop"


def test_send(adapter):
    adapter._validate_messages = Mock()
    adapter._send_request = Mock()
    adapter._parse_response = Mock()

    fake_response = Mock()
    adapter._send_request.return_value = fake_response

    expected_result = {
        "role": "assistant",
        "content": "Hello",
        "tool_calls": None,
        "finish_reason": "stop",
    }

    adapter._parse_response.return_value = expected_result

    messages = [
        {
            "role": "user",
            "content": "Hello"
        }
    ]

    result = adapter.send(messages)

    assert result == expected_result
    adapter._validate_messages.assert_called_once_with(messages)
    adapter._send_request.assert_called_once_with(messages, None)
    adapter._parse_response.assert_called_once_with(fake_response)
    
def test_send_request_success(adapter):
    fake_response = Mock()
    adapter.client = Mock()

    adapter.client.chat.completions.create.return_value = fake_response
    messages = [
        {
            "role": "user",
            "content": "Hello"
        }
    ]

    result = adapter._send_request(messages)

    assert result == fake_response
    adapter.client.chat.completions.create.assert_called_once_with(
        model="test-model",
        messages=messages,
    )


def test_authentication_error(adapter):
    adapter.client = Mock()
    adapter.client.chat.completions.create.side_effect = AuthenticationError(
        message="Invalid API Key",
        response=Mock(status_code=401),
        body=None
    )

    with pytest.raises(RuntimeError) as exc_info:
        adapter._send_request([{"role": "user", "content": "hi"}])
    
    assert "Invalid API Key or unauthorized access" in str(exc_info.value)

def test_rate_limit_error(adapter):
    adapter.client = Mock()
    adapter.client.chat.completions.create.side_effect = RateLimitError(
        message="Rate limit exceeded",
        response=Mock(status_code=429),
        body=None
    )

    with pytest.raises(RuntimeError) as exc_info:
        adapter._send_request([{"role": "user", "content": "hi"}])
    
    assert "Quota exceeded or rate limit reached" in str(exc_info.value)

def test_connection_error(adapter):
    adapter.client = Mock()
    adapter.client.chat.completions.create.side_effect = APIConnectionError(
        message="Connection failed",
        request=None
    )

    with pytest.raises(RuntimeError) as exc_info:
        adapter._send_request([{"role": "user", "content": "hi"}])
    
    assert "Failed to connect to the API" in str(exc_info.value)