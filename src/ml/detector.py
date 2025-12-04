"""
ML-based Reentrancy Detector

Combines feature extraction with ML classification for
vulnerability detection.
"""

from pathlib import Path
from typing import List, Optional
import uuid

from ..detectors.reentrancy.base import (
    ReentrancyDetector,
    ReentrancyVulnerability,
    VulnerabilityLocation,
    ReentrancyType,
    Severity,
)
from .features import FeatureExtractor, ContractFeatures
from .model import ReentrancyClassifier, PredictionResult


class MLReentrancyDetector(ReentrancyDetector):
    """
    Machine learning-based reentrancy detector.
    
    Uses feature extraction and ML classification to identify
    potential reentrancy vulnerabilities.
    
    Features:
    - Pattern-based feature extraction
    - Multiple ML model support
    - Confidence scoring
    - Risk factor identification
    
    Usage:
        detector = MLReentrancyDetector()
        vulnerabilities = detector.analyze(Path("contract.sol"))
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        model_type: str = "random_forest",
        min_confidence: float = 0.6,
    ):
        """
        Initialize the ML detector.
        
        Args:
            model_path: Path to pre-trained model (optional)
            model_type: Type of ML model to use
            min_confidence: Minimum confidence threshold for reporting
        """
        self.feature_extractor = FeatureExtractor()
        self.classifier = ReentrancyClassifier(model_type=model_type)
        self.min_confidence = min_confidence
        
        if model_path and Path(model_path).exists():
            self.classifier.load(model_path)
    
    @property
    def name(self) -> str:
        return "ML Reentrancy Detector"
    
    @property
    def description(self) -> str:
        return (
            "Machine learning-based detector that uses feature extraction "
            "and classification to identify reentrancy vulnerabilities. "
            "Analyzes code patterns, external calls, state modifications, "
            "and protection mechanisms."
        )
    
    @property
    def reentrancy_type(self) -> ReentrancyType:
        return ReentrancyType.MONO_FUNCTION  # Can detect multiple types
    
    def analyze(self, contract_path: Path) -> List[ReentrancyVulnerability]:
        """
        Analyze a contract for reentrancy vulnerabilities using ML.
        
        Args:
            contract_path: Path to the contract file
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Read contract
        with open(contract_path, 'r') as f:
            source_code = f.read()
        
        # Extract features
        features = self.feature_extractor.extract_from_source(source_code)
        feature_vector = self.feature_extractor.to_vector(features)
        
        # Get ML prediction
        prediction = self.classifier.predict(feature_vector)
        
        # Create vulnerability if detected
        if prediction.is_vulnerable and prediction.confidence >= self.min_confidence:
            vuln = self._create_vulnerability(
                contract_path=contract_path,
                features=features,
                prediction=prediction,
                source_code=source_code,
            )
            vulnerabilities.append(vuln)
        
        # Also check for specific high-risk patterns
        pattern_vulns = self._check_high_risk_patterns(
            contract_path=contract_path,
            features=features,
            source_code=source_code,
        )
        vulnerabilities.extend(pattern_vulns)
        
        return vulnerabilities
    
    def analyze_bytecode(self, bytecode: str) -> List[ReentrancyVulnerability]:
        """
        Analyze bytecode for reentrancy vulnerabilities.
        
        Args:
            bytecode: Hex-encoded EVM bytecode
            
        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        
        # Extract bytecode features
        features = self.feature_extractor.extract_from_bytecode(bytecode)
        
        # Check for CALL -> SSTORE pattern
        if features.call_sstore_distance < 20 and features.num_call_opcodes > 0:
            vuln = ReentrancyVulnerability(
                id=str(uuid.uuid4()),
                title="ML: Potential Reentrancy Pattern in Bytecode",
                type=ReentrancyType.MONO_FUNCTION,
                severity=Severity.MEDIUM,
                confidence=0.7,
                description=(
                    f"Bytecode analysis detected SSTORE opcode occurring "
                    f"{features.call_sstore_distance} instructions after CALL opcode. "
                    f"This pattern may indicate state modification after external call."
                ),
                attack_vector=(
                    "If state is modified after an external call, an attacker "
                    "may be able to re-enter the contract and exploit the "
                    "inconsistent state."
                ),
                recommendation=(
                    "Review the contract source code to ensure state modifications "
                    "occur before external calls (Checks-Effects-Interactions pattern)."
                ),
                location=VulnerabilityLocation(
                    file_path="bytecode",
                    contract_name="Unknown",
                    function_name="Unknown",
                    line_start=0,
                    line_end=0,
                ),
                references=[
                    "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
                ],
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _create_vulnerability(
        self,
        contract_path: Path,
        features: ContractFeatures,
        prediction: PredictionResult,
        source_code: str,
    ) -> ReentrancyVulnerability:
        """Create a vulnerability object from ML prediction."""
        
        # Determine severity based on confidence and risk factors
        if prediction.confidence > 0.85:
            severity = Severity.HIGH
        elif prediction.confidence > 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        # Determine reentrancy type based on features
        if features.has_erc777_interaction or features.has_erc721_interaction:
            vuln_type = ReentrancyType.CROSS_CONTRACT
        elif features.state_write_after_call > 1:
            vuln_type = ReentrancyType.CROSS_FUNCTION
        else:
            vuln_type = ReentrancyType.MONO_FUNCTION
        
        # Build description
        risk_factors = prediction.risk_factors or features.vulnerability_indicators
        risk_str = ", ".join(risk_factors) if risk_factors else "pattern analysis"
        
        description = (
            f"ML analysis detected potential reentrancy vulnerability with "
            f"{prediction.confidence:.0%} confidence. Risk factors: {risk_str}. "
            f"The contract has {features.num_external_calls} external calls and "
            f"{features.state_write_after_call} state writes after external calls."
        )
        
        # Build attack vector
        attack_vector = self._build_attack_vector(features)
        
        # Build recommendation
        recommendation = self._build_recommendation(features)
        
        return ReentrancyVulnerability(
            id=str(uuid.uuid4()),
            title=f"ML: Reentrancy Vulnerability Detected ({prediction.model_used})",
            type=vuln_type,
            severity=severity,
            confidence=prediction.confidence,
            description=description,
            attack_vector=attack_vector,
            recommendation=recommendation,
            location=VulnerabilityLocation(
                file_path=str(contract_path),
                contract_name=contract_path.stem,
                function_name="Multiple",
                line_start=1,
                line_end=len(source_code.splitlines()),
            ),
            has_reentrancy_guard=features.has_reentrancy_guard,
            suggested_fix=self._generate_fix_suggestion(features),
            references=[
                "https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard",
                "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            ],
        )
    
    def _check_high_risk_patterns(
        self,
        contract_path: Path,
        features: ContractFeatures,
        source_code: str,
    ) -> List[ReentrancyVulnerability]:
        """Check for specific high-risk patterns."""
        vulnerabilities = []
        
        # ERC777 callback risk
        if features.has_erc777_interaction and not features.has_reentrancy_guard:
            vuln = ReentrancyVulnerability(
                id=str(uuid.uuid4()),
                title="ML: ERC777 Callback Reentrancy Risk",
                type=ReentrancyType.CROSS_CONTRACT,
                severity=Severity.HIGH,
                confidence=0.8,
                description=(
                    "Contract interacts with ERC777 tokens without reentrancy protection. "
                    "ERC777 tokens trigger callbacks (tokensReceived, tokensToSend) that "
                    "can be exploited for reentrancy attacks."
                ),
                attack_vector=(
                    "1. Attacker deploys malicious ERC777 token or uses existing one\n"
                    "2. Attacker triggers token transfer to/from this contract\n"
                    "3. ERC777 callback is triggered during transfer\n"
                    "4. Attacker re-enters contract functions during callback\n"
                    "5. State is manipulated before original transaction completes"
                ),
                recommendation=(
                    "1. Add ReentrancyGuard to all functions interacting with ERC777\n"
                    "2. Consider using ERC20 instead if ERC777 features not needed\n"
                    "3. Follow Checks-Effects-Interactions pattern strictly"
                ),
                location=VulnerabilityLocation(
                    file_path=str(contract_path),
                    contract_name=contract_path.stem,
                    function_name="ERC777 interactions",
                    line_start=1,
                    line_end=len(source_code.splitlines()),
                ),
                references=[
                    "https://blog.openzeppelin.com/exploiting-uniswap-from-reentrancy-to-actual-profit",
                ],
            )
            vulnerabilities.append(vuln)
        
        # Flash loan callback risk
        if features.has_flash_loan_callback and not features.has_reentrancy_guard:
            vuln = ReentrancyVulnerability(
                id=str(uuid.uuid4()),
                title="ML: Flash Loan Callback Reentrancy Risk",
                type=ReentrancyType.CROSS_CONTRACT,
                severity=Severity.HIGH,
                confidence=0.75,
                description=(
                    "Contract implements flash loan callback without reentrancy protection. "
                    "Flash loan callbacks can be exploited to manipulate contract state "
                    "or pricing during the callback execution."
                ),
                attack_vector=(
                    "1. Attacker takes flash loan from lending protocol\n"
                    "2. Flash loan triggers callback to this contract\n"
                    "3. During callback, attacker manipulates state/prices\n"
                    "4. Attacker profits from manipulated state\n"
                    "5. Flash loan is repaid, attack complete"
                ),
                recommendation=(
                    "1. Add ReentrancyGuard to flash loan callbacks\n"
                    "2. Validate callback caller is legitimate flash loan provider\n"
                    "3. Use time-weighted average prices (TWAP) for pricing\n"
                    "4. Implement proper access controls on callbacks"
                ),
                location=VulnerabilityLocation(
                    file_path=str(contract_path),
                    contract_name=contract_path.stem,
                    function_name="Flash loan callback",
                    line_start=1,
                    line_end=len(source_code.splitlines()),
                ),
                references=[
                    "https://www.paradigm.xyz/2020/11/so-you-want-to-use-a-price-oracle",
                ],
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _build_attack_vector(self, features: ContractFeatures) -> str:
        """Build attack vector description based on features."""
        vectors = []
        
        if features.state_write_after_call > 0:
            vectors.append(
                "1. Attacker calls vulnerable function\n"
                "2. Function makes external call to attacker contract\n"
                "3. Attacker's fallback re-enters before state update\n"
                "4. State is manipulated in inconsistent state\n"
                "5. Original function completes with corrupted state"
            )
        
        if features.has_erc777_interaction:
            vectors.append(
                "ERC777 tokens trigger callbacks during transfers that "
                "can be used to re-enter the contract."
            )
        
        if features.has_flash_loan_callback:
            vectors.append(
                "Flash loan callbacks execute arbitrary code that can "
                "manipulate contract state during the loan."
            )
        
        return "\n\n".join(vectors) if vectors else "See vulnerability description."
    
    def _build_recommendation(self, features: ContractFeatures) -> str:
        """Build recommendation based on features."""
        recommendations = []
        
        if not features.has_reentrancy_guard:
            recommendations.append(
                "Add OpenZeppelin's ReentrancyGuard and apply nonReentrant "
                "modifier to all state-changing external functions."
            )
        
        if features.state_write_after_call > 0:
            recommendations.append(
                "Follow Checks-Effects-Interactions pattern: update all "
                "state variables BEFORE making external calls."
            )
        
        if features.has_erc777_interaction:
            recommendations.append(
                "Consider using ERC20 instead of ERC777 if advanced "
                "features are not needed, or add reentrancy protection."
            )
        
        if not recommendations:
            recommendations.append(
                "Review contract for potential reentrancy vectors and "
                "apply appropriate protections."
            )
        
        return " ".join(recommendations)
    
    def _generate_fix_suggestion(self, features: ContractFeatures) -> str:
        """Generate fix suggestion based on features."""
        return '''
// Add OpenZeppelin's ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureContract is ReentrancyGuard {
    // Apply nonReentrant to all state-changing functions
    function vulnerableFunction() external nonReentrant {
        // 1. CHECKS - Validate all conditions first
        require(condition, "Validation failed");
        
        // 2. EFFECTS - Update ALL state variables
        stateVariable = newValue;
        balances[msg.sender] = 0;
        
        // 3. INTERACTIONS - External calls LAST
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
'''
    
    def generate_fix_suggestion(self, vulnerability: ReentrancyVulnerability) -> str:
        """Generate fix suggestion for a vulnerability."""
        return self._generate_fix_suggestion(ContractFeatures())
