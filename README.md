# LogTranscriber

Tool to extract, parse, and decode Nginx access logs containing JWT tokens.

## Setup

1.  **Create a Virtual Environment**:
    ```bash
    python3 -m venv venv
    ```

2.  **Activate the Environment**:
    *   **macOS/Linux**:
        ```bash
        source venv/bin/activate
        ```
    *   **Windows**:
        ```bash
        .\venv\Scripts\activate
        ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configuration**:
    *   Copy `.env` and fill in your credentials:
        ```ini
        SSH_HOST=...
        SSH_USER=...
        SSH_PASS=...
        JWT_SECRET=...
        ```

## Usage

Run the main script:
```bash
python app.py
```

## Testing

Run unit tests:
```bash
python -m unittest tests/test_parser.py
```
