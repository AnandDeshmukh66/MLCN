"""python -m traffic_generator.streamlit_app"""

import sys
from pathlib import Path

# Delegate to Streamlit CLI for `python -m traffic_generator`.
import streamlit.web.cli as stcli

if __name__ == "__main__":
    app = Path(__file__).resolve().parent / "streamlit_app.py"
    sys.argv = ["streamlit", "run", str(app), *sys.argv[1:]]
    sys.exit(stcli.main())
