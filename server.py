#!/usr/bin/env python3
"""
ReGuardian Web Server

Starts both the API backend and serves the frontend.

Usage:
    python3 server.py
    
Then open: http://localhost:8000
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

# Create a new app that will serve frontend + API
app = FastAPI(
    title="ReGuardian",
    description="AI-Powered Smart Contract Reentrancy Vulnerability Detection",
    version="0.1.0",
)

# Add CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import and mount the API routes
from src.api.main import app as api_app

# Copy all routes from api_app to main app under /api prefix
for route in api_app.routes:
    if hasattr(route, 'path') and route.path not in ['/', '/docs', '/redoc', '/openapi.json']:
        app.routes.append(route)

# Also add routes without prefix for backward compatibility
from src.api.main import (
    health_check, analyze_source, analyze_file, analyze_bytecode,
    get_attacks, get_patterns, get_statistics
)

app.add_api_route("/health", health_check, methods=["GET"])
app.add_api_route("/analyze", analyze_source, methods=["POST"])
app.add_api_route("/analyze/file", analyze_file, methods=["POST"])
app.add_api_route("/analyze/bytecode", analyze_bytecode, methods=["POST"])
app.add_api_route("/attacks", get_attacks, methods=["GET"])
app.add_api_route("/patterns", get_patterns, methods=["GET"])
app.add_api_route("/statistics", get_statistics, methods=["GET"])

# Frontend path
frontend_path = Path(__file__).parent / "frontend"

# Serve frontend at root
@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the frontend HTML."""
    index_file = frontend_path / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(), status_code=200)
    else:
        return HTMLResponse(content="<h1>Frontend not found</h1>", status_code=404)

# Serve static files
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")


def main():
    """Start the ReGuardian web server."""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🛡️  ReGuardian Web Server                                      ║
║                                                                  ║
║   Starting server...                                             ║
║                                                                  ║
║   Frontend:  http://localhost:8000                               ║
║   API Docs:  http://localhost:8000/docs                          ║
║   ReDoc:     http://localhost:8000/redoc                         ║
║                                                                  ║
║   Press Ctrl+C to stop                                           ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        reload_dirs=[str(Path(__file__).parent / "src")],
    )


if __name__ == "__main__":
    main()
