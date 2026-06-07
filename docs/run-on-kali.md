# Run NetWatch on Kali Linux

These commands work well with Kali and the fish shell.

## 1. Install venv support

```fish
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
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
python -m streamlit run app.py
```

Open the URL shown by Streamlit, usually:

```text
http://localhost:8501
```

## Useful checks

```fish
which python
which pip
python --version
pytest -q
```

`which python` should point to `NetWatch/venv/bin/python`.
