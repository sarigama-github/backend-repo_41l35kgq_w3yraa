import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, Literal
import requests
from datetime import datetime, timezone

from database import db

app = FastAPI(title="Security Hub Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LogEntry(BaseModel):
    user_id: Optional[str] = None
    type: Literal[
        "phishing_warning",
        "ad_blocked",
        "download_scanned",
        "suspicious_behavior",
        "login",
        "logout",
        "settings_change",
        "info",
    ]
    message: str
    data: Optional[dict] = None


class SettingsPayload(BaseModel):
    user_id: Optional[str] = None
    ad_blocker_enabled: bool = True
    phishing_protection_enabled: bool = True
    download_scanner_enabled: bool = True
    behavior_detector_enabled: bool = True


@app.get("/")
def read_root():
    return {"message": "Security Hub API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, "name") else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


@app.post("/api/logs")
def add_log(entry: LogEntry):
    if db is None:
        # Soft-fail if DB is not configured
        return {"status": "ok", "warning": "database not configured"}
    doc = entry.model_dump()
    doc["created_at"] = datetime.now(timezone.utc)
    db["logs"].insert_one(doc)
    return {"status": "ok"}


@app.get("/api/logs")
def get_logs(user_id: Optional[str] = None, limit: int = 100):
    if db is None:
        return {"items": []}
    flt = {"user_id": user_id} if user_id else {}
    items = list(db["logs"].find(flt).sort("created_at", -1).limit(limit))
    for it in items:
        it["_id"] = str(it["_id"])
    return {"items": items}


@app.post("/api/settings")
def save_settings(payload: SettingsPayload):
    if not payload.user_id:
        raise HTTPException(status_code=400, detail="user_id required for settings sync")
    if db is None:
        return {"status": "ok", "warning": "database not configured"}
    doc = payload.model_dump()
    doc["updated_at"] = datetime.now(timezone.utc)
    db["settings"].update_one({"user_id": payload.user_id}, {"$set": doc}, upsert=True)
    return {"status": "ok"}


@app.get("/api/settings")
def fetch_settings(user_id: str):
    if db is None:
        return {
            "ad_blocker_enabled": True,
            "phishing_protection_enabled": True,
            "download_scanner_enabled": True,
            "behavior_detector_enabled": True,
        }
    item = db["settings"].find_one({"user_id": user_id})
    if not item:
        return {
            "ad_blocker_enabled": True,
            "phishing_protection_enabled": True,
            "download_scanner_enabled": True,
            "behavior_detector_enabled": True,
        }
    item.pop("_id", None)
    return item


@app.get("/api/breach-check")
def breach_check(email: EmailStr):
    hibp_key = os.getenv("HIBP_API_KEY")
    if not hibp_key:
        # No key configured – return a safe default
        return {"email": email, "exposed": False, "source": "none"}
    try:
        headers = {
            "hibp-api-key": hibp_key,
            "user-agent": "SecurityHub/1.0 (extension)",
        }
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=headers,
            params={"truncateResponse": True},
            timeout=10,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "email": email,
                "exposed": len(breaches) > 0,
                "count": len(breaches),
                "source": "hibp",
            }
        if r.status_code == 404:
            return {"email": email, "exposed": False, "source": "hibp"}
        raise HTTPException(status_code=r.status_code, detail=r.text[:200])
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:200])


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
