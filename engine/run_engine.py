"""
BGP-Shield Engine Runner
Starts the FastAPI API Bridge and RIPE RIS Live Stream Ingestion.
"""
import sys
from pathlib import Path

# Add current directory to path
current_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(current_dir))

import uvicorn
from config import API_HOST, API_PORT

if __name__ == "__main__":
    print(f"[*] Starting BGP-Shield Sentinel Engine on http://{API_HOST}:{API_PORT}")
    uvicorn.run("api_bridge:app", host=API_HOST, port=API_PORT, reload=False)
