from fastapi import FastAPI, Request, Header, HTTPException
import subprocess
import re
import os
import logging

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "dein-geheimes-token")

app = FastAPI()

# Logging konfigurieren
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[logging.FileHandler("webhook_server.log"), logging.StreamHandler()]
)

def extract_prefix(domain):
    """Entfernt TLD und Punkt, z.B. praxis-website.de -> praxis-website"""
    return re.sub(r'\.[a-zA-Z0-9\-]+$', '', domain)

@app.post("/webhook/create-site")
async def create_site_webhook(request: Request, x_webhook_secret: str = Header(None)):
    if x_webhook_secret != WEBHOOK_SECRET:
        logging.warning(f"Unauthorized attempt with secret: {x_webhook_secret}")
        raise HTTPException(status_code=403, detail="Forbidden")
    data = await request.json()
    old_domain = data.get("old_domain")
    if not old_domain:
        logging.error("old_domain missing in request")
        raise HTTPException(status_code=400, detail="old_domain missing")
    prefix = extract_prefix(old_domain)
    # Weitere Validierung
    if not re.match(r'^[a-zA-Z0-9\-]+$', prefix):
        logging.error(f"Invalid prefix extracted: {prefix}")
        raise HTTPException(status_code=400, detail="Invalid prefix")
    logging.info(f"Received request for old_domain={old_domain}, extracted prefix={prefix}")
    # CLI-Aufruf
    try:
        result = subprocess.run(
            ["python3", "src/ionos_wp_manager.py", "create-site", prefix],
            capture_output=True, text=True, timeout=300
        )
        logging.info(f"CLI stdout: {result.stdout}")
        if result.stderr:
            logging.error(f"CLI stderr: {result.stderr}")
        return {
            "prefix": prefix,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        logging.error("CLI call timed out")
        raise HTTPException(status_code=504, detail="CLI call timed out")
    except Exception as e:
        logging.error(f"Exception during CLI call: {e}")
        raise HTTPException(status_code=500, detail=str(e))
