# Backend Adapter

A lightweight backend adapter for communicating with OpenAI-compatible APIs.

## Features

- Validate messages before sending requests.
- Send chat completion requests.
- Parse API responses.
- Handle common API errors.
- Unit tests using pytest.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Run the demo:

```bash
python demo.py
```

## Running Tests

```bash
pytest
```

## Project Structure

```
.
├── adapter.py
├── demo.py
├── test_adapter.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```