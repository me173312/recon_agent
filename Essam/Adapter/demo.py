import os
from dotenv import load_dotenv

from adapter import BackendAdapter

load_dotenv()

adapter = BackendAdapter(
    base_url=os.getenv("BASE_URL"),
    api_key=os.getenv("API_KEY"),
    model=os.getenv("MODEL"),
)

messages = [
    {
        "role": "user",
        "content": "Hello!"
    }
]

result = adapter.send(messages)

print(result)