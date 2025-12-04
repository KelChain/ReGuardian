"""
ReGuardian API

FastAPI-based REST API for ReGuardian reentrancy detection.

Usage:
    uvicorn src.api.main:app --reload --port 8000
    
Endpoints:
    POST /analyze - Analyze contract source code
    POST /analyze/file - Analyze uploaded contract file
    POST /analyze/bytecode - Analyze EVM bytecode
    GET /health - Health check
    GET /attacks - Get attack database
"""

import os
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Dict, Any
from enum import Enum

from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import json

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.core.reguardian import ReGuardian, ReGuardianConfig, AnalysisMode
from src.detectors.reentrancy.base import Severity


# ============================================================================
# Pydantic Models
# ============================================================================

class AnalysisModeEnum(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"
    full = "full"


class SeverityEnum(str, Enum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AnalyzeRequest(BaseModel):
    """Request model for contract analysis."""
    source_code: str = Field(..., description="Solidity/Vyper source code")
    contract_name: str = Field(default="Contract.sol", description="Contract filename")
    mode: AnalysisModeEnum = Field(default=AnalysisModeEnum.standard)
    min_severity: SeverityEnum = Field(default=SeverityEnum.low)
    generate_fixes: bool = Field(default=True)


class BytecodeRequest(BaseModel):
    """Request model for bytecode analysis."""
    bytecode: str = Field(..., description="Hex-encoded EVM bytecode")
    mode: AnalysisModeEnum = Field(default=AnalysisModeEnum.quick)


class VulnerabilityResponse(BaseModel):
    """Response model for a single vulnerability."""
    id: str
    title: str
    type: str
    severity: str
    confidence: float
    description: str
    attack_vector: str
    recommendation: str
    suggested_fix: Optional[str]
    location: Dict[str, Any]
    references: List[str]


class AnalysisResponse(BaseModel):
    """Response model for analysis results."""
    success: bool
    contract: str
    analysis_time: float
    total_vulnerabilities: int
    critical: int
    high: int
    medium: int
    low: int
    vulnerabilities: List[VulnerabilityResponse]
    warnings: List[str]


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    tools: Dict[str, bool]


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(
    title="ReGuardian API",
    description="AI-Powered Smart Contract Reentrancy Vulnerability Detection",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# Helper Functions
# ============================================================================

def get_mode(mode: AnalysisModeEnum) -> AnalysisMode:
    """Convert API mode to internal mode."""
    return {
        AnalysisModeEnum.quick: AnalysisMode.QUICK,
        AnalysisModeEnum.standard: AnalysisMode.STANDARD,
        AnalysisModeEnum.deep: AnalysisMode.DEEP,
        AnalysisModeEnum.full: AnalysisMode.FULL,
    }[mode]


def get_severity(severity: SeverityEnum) -> Severity:
    """Convert API severity to internal severity."""
    return {
        SeverityEnum.informational: Severity.INFORMATIONAL,
        SeverityEnum.low: Severity.LOW,
        SeverityEnum.medium: Severity.MEDIUM,
        SeverityEnum.high: Severity.HIGH,
        SeverityEnum.critical: Severity.CRITICAL,
    }[severity]


def vuln_to_response(vuln) -> VulnerabilityResponse:
    """Convert vulnerability to response model."""
    return VulnerabilityResponse(
        id=vuln.id,
        title=vuln.title,
        type=vuln.type.value,
        severity=vuln.severity.value,
        confidence=vuln.confidence,
        description=vuln.description,
        attack_vector=vuln.attack_vector,
        recommendation=vuln.recommendation,
        suggested_fix=vuln.suggested_fix,
        location={
            "file": vuln.location.file_path,
            "contract": vuln.location.contract_name,
            "function": vuln.location.function_name,
            "line_start": vuln.location.line_start,
            "line_end": vuln.location.line_end,
        },
        references=vuln.references,
    )


def check_tool_availability() -> Dict[str, bool]:
    """Check which tools are available."""
    import shutil
    return {
        "slither": shutil.which("slither") is not None,
        "mythril": shutil.which("myth") is not None,
        "solc": shutil.which("solc") is not None,
    }


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with API info."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReGuardian API</title>
        <style>
            body { font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; padding: 40px; }
            h1 { color: #667eea; }
            a { color: #70a1ff; }
            .endpoint { background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }
            code { background: #0f0f23; padding: 2px 6px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>🛡️ ReGuardian API</h1>
        <p>AI-Powered Smart Contract Reentrancy Vulnerability Detection</p>
        
        <h2>Endpoints</h2>
        <div class="endpoint">
            <strong>POST /analyze</strong> - Analyze contract source code<br>
            <code>{"source_code": "...", "mode": "standard"}</code>
        </div>
        <div class="endpoint">
            <strong>POST /analyze/file</strong> - Upload and analyze contract file
        </div>
        <div class="endpoint">
            <strong>POST /analyze/bytecode</strong> - Analyze EVM bytecode<br>
            <code>{"bytecode": "0x..."}</code>
        </div>
        <div class="endpoint">
            <strong>GET /attacks</strong> - Get historical attack database
        </div>
        <div class="endpoint">
            <strong>GET /health</strong> - Health check
        </div>
        
        <p>📚 <a href="/docs">Interactive API Documentation (Swagger)</a></p>
        <p>📖 <a href="/redoc">ReDoc Documentation</a></p>
    </body>
    </html>
    """


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        tools=check_tool_availability(),
    )


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_source(request: AnalyzeRequest):
    """
    Analyze Solidity/Vyper source code for reentrancy vulnerabilities.
    
    - **source_code**: The contract source code
    - **contract_name**: Filename for the contract (default: Contract.sol)
    - **mode**: Analysis depth (quick, standard, deep, full)
    - **min_severity**: Minimum severity to report
    - **generate_fixes**: Whether to generate fix suggestions
    """
    try:
        # Create temp file with source code
        suffix = ".sol" if request.contract_name.endswith(".sol") else ".vy"
        with tempfile.NamedTemporaryFile(
            mode='w', 
            suffix=suffix, 
            delete=False,
            prefix="reguardian_"
        ) as f:
            f.write(request.source_code)
            temp_path = f.name
        
        try:
            # Configure and run analysis
            config = ReGuardianConfig(
                mode=get_mode(request.mode),
                min_severity=get_severity(request.min_severity),
                generate_fixes=request.generate_fixes,
            )
            
            rg = ReGuardian(config)
            result = rg.analyze(temp_path)
            summary = rg.get_summary(result)
            
            return AnalysisResponse(
                success=True,
                contract=request.contract_name,
                analysis_time=result.analysis_time_seconds,
                total_vulnerabilities=summary['total_vulnerabilities'],
                critical=summary['critical'],
                high=summary['high'],
                medium=summary['medium'],
                low=summary['low'],
                vulnerabilities=[vuln_to_response(v) for v in result.vulnerabilities],
                warnings=result.warnings,
            )
        finally:
            # Clean up temp file
            os.unlink(temp_path)
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/analyze/file", response_model=AnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    mode: AnalysisModeEnum = AnalysisModeEnum.standard,
    min_severity: SeverityEnum = SeverityEnum.low,
):
    """
    Upload and analyze a contract file.
    
    - **file**: Solidity (.sol) or Vyper (.vy) contract file
    - **mode**: Analysis depth
    - **min_severity**: Minimum severity to report
    """
    if not file.filename.endswith(('.sol', '.vy')):
        raise HTTPException(
            status_code=400, 
            detail="File must be .sol or .vy"
        )
    
    try:
        content = await file.read()
        source_code = content.decode('utf-8')
        
        request = AnalyzeRequest(
            source_code=source_code,
            contract_name=file.filename,
            mode=mode,
            min_severity=min_severity,
        )
        
        return await analyze_source(request)
        
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Invalid file encoding")


@app.post("/analyze/bytecode", response_model=AnalysisResponse)
async def analyze_bytecode(request: BytecodeRequest):
    """
    Analyze EVM bytecode for reentrancy vulnerabilities.
    
    - **bytecode**: Hex-encoded bytecode (with or without 0x prefix)
    - **mode**: Analysis depth
    """
    try:
        bytecode = request.bytecode
        if not bytecode.startswith('0x'):
            bytecode = '0x' + bytecode
        
        config = ReGuardianConfig(mode=get_mode(request.mode))
        rg = ReGuardian(config)
        
        result = rg.analyze_bytecode(bytecode)
        summary = rg.get_summary(result)
        
        return AnalysisResponse(
            success=True,
            contract="bytecode",
            analysis_time=result.analysis_time_seconds,
            total_vulnerabilities=summary['total_vulnerabilities'],
            critical=summary['critical'],
            high=summary['high'],
            medium=summary['medium'],
            low=summary['low'],
            vulnerabilities=[vuln_to_response(v) for v in result.vulnerabilities],
            warnings=result.warnings,
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/attacks")
async def get_attacks():
    """Get the historical reentrancy attack database."""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "attacks" / "attack_database.json"
        
        if not db_path.exists():
            raise HTTPException(status_code=404, detail="Attack database not found")
        
        with open(db_path) as f:
            return json.load(f)
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid attack database format")


@app.get("/patterns")
async def get_patterns():
    """Get known vulnerability patterns."""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "attacks" / "attack_database.json"
        
        if not db_path.exists():
            raise HTTPException(status_code=404, detail="Attack database not found")
        
        with open(db_path) as f:
            data = json.load(f)
            return data.get("patterns", {})
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid database format")


@app.get("/statistics")
async def get_statistics():
    """Get attack statistics."""
    try:
        db_path = Path(__file__).parent.parent.parent / "data" / "attacks" / "attack_database.json"
        
        if not db_path.exists():
            raise HTTPException(status_code=404, detail="Attack database not found")
        
        with open(db_path) as f:
            data = json.load(f)
            return data.get("statistics", {})
            
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid database format")


# ============================================================================
# Run with: uvicorn src.api.main:app --reload
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
