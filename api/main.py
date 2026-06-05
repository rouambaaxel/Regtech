"""
ComplianceOS — Application Entry Point
Run: uvicorn main:app --reload --host 0.0.0.0 --port 8000
"""

from dotenv import load_dotenv
load_dotenv()

from routes import app
from auth import router as auth_router

app.include_router(auth_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
