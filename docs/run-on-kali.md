# Run NetWatch on Kali Linux

These commands work well with Kali and the fish shell.

## 1. Install venv support

```fish
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iputils-ping
```

## 2. Clone and enter the project

```fish
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
```

If the folder already exists:

```fish
cd NetWatch
git pull
```

## 3. Create and activate the virtual environment

```fish
python3 -m venv venv
source venv/bin/activate.fish
```

You should see `(venv)` in the prompt.

## 4. Install dependencies

```fish
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Run the app

```fish
set -x NETWATCH_API_KEY (python -c 'import secrets; print(secrets.token_urlsafe(32))')
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open the secured FastAPI dashboard:

```text
http://127.0.0.1:8000
```

For a local break-glass login, use the key stored in `$NETWATCH_API_KEY`. The old Streamlit frontend is temporarily disabled because its Pillow dependency blocks current security patches.

## Useful checks

```fish
which python
which pip
python --version
pytest -q
```

`which python` should point to `NetWatch/venv/bin/python`.
