"""
Feature Extraction for ML-based Reentrancy Detection

Extracts features from Solidity source code and EVM bytecode
for machine learning classification.
"""

import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import hashlib


@dataclass
class ContractFeatures:
    """Features extracted from a smart contract."""
    
    # Basic metrics
    num_functions: int = 0
    num_external_functions: int = 0
    num_public_functions: int = 0
    num_payable_functions: int = 0
    num_state_variables: int = 0
    num_mappings: int = 0
    
    # External call patterns
    num_external_calls: int = 0
    num_low_level_calls: int = 0  # .call, .delegatecall, .staticcall
    num_transfer_calls: int = 0
    num_send_calls: int = 0
    has_fallback: bool = False
    has_receive: bool = False
    
    # State modification patterns
    num_state_writes: int = 0
    num_state_reads: int = 0
    state_write_after_call: int = 0  # Key reentrancy indicator
    
    # Protection patterns
    has_reentrancy_guard: bool = False
    has_nonreentrant_modifier: bool = False
    has_mutex_lock: bool = False
    uses_checks_effects_interactions: bool = False
    
    # Token patterns
    has_erc20_interaction: bool = False
    has_erc721_interaction: bool = False
    has_erc777_interaction: bool = False
    has_flash_loan_callback: bool = False
    
    # Complexity metrics
    cyclomatic_complexity: int = 0
    max_call_depth: int = 0
    num_loops: int = 0
    num_conditionals: int = 0
    
    # Bytecode features (if available)
    bytecode_length: int = 0
    num_call_opcodes: int = 0
    num_sstore_opcodes: int = 0
    num_sload_opcodes: int = 0
    call_sstore_distance: int = 0  # Opcodes between CALL and SSTORE
    
    # Risk indicators
    risk_score: float = 0.0
    vulnerability_indicators: List[str] = field(default_factory=list)


class FeatureExtractor:
    """
    Extract features from smart contracts for ML classification.
    
    Features are designed to capture patterns associated with
    reentrancy vulnerabilities.
    """
    
    # Regex patterns for feature extraction
    PATTERNS = {
        'function': r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?',
        'external_func': r'function\s+\w+\s*\([^)]*\)\s*(external|public)',
        'payable': r'function\s+\w+[^{]*payable',
        'state_var': r'^\s*(uint|int|bool|address|bytes|string|mapping)\d*\s+\w+',
        'mapping': r'mapping\s*\([^)]+\)',
        
        # External calls
        'low_level_call': r'\.(call|delegatecall|staticcall)\s*[({]',
        'transfer': r'\.transfer\s*\(',
        'send': r'\.send\s*\(',
        'external_call': r'\.\w+\s*\{[^}]*value\s*:',
        
        # State operations
        'state_write': r'(\w+)\s*(\[.+\])?\s*[+\-*/]?=',
        'state_read': r'=\s*(\w+)\s*(\[.+\])?',
        
        # Protection patterns
        'reentrancy_guard': r'ReentrancyGuard|nonReentrant|_status|_notEntered',
        'mutex': r'(locked|mutex|_lock)\s*=\s*(true|false|1|0)',
        
        # Token patterns
        'erc20': r'(IERC20|ERC20|transfer|transferFrom|approve|allowance)',
        'erc721': r'(IERC721|ERC721|safeTransferFrom|onERC721Received)',
        'erc777': r'(IERC777|ERC777|tokensReceived|tokensToSend)',
        'flash_loan': r'(flashLoan|executeOperation|onFlashLoan)',
        
        # Control flow
        'loop': r'(for|while)\s*\(',
        'conditional': r'(if|else|require|assert)\s*\(',
        
        # Fallback/receive
        'fallback': r'fallback\s*\(\s*\)',
        'receive': r'receive\s*\(\s*\)\s*external\s*payable',
    }
    
    # Bytecode opcodes
    OPCODES = {
        'CALL': 'f1',
        'CALLCODE': 'f2',
        'DELEGATECALL': 'f4',
        'STATICCALL': 'fa',
        'SSTORE': '55',
        'SLOAD': '54',
        'JUMPI': '57',
        'JUMP': '56',
    }
    
    def __init__(self):
        self.compiled_patterns = {
            name: re.compile(pattern, re.MULTILINE | re.IGNORECASE)
            for name, pattern in self.PATTERNS.items()
        }
    
    def extract_from_source(self, source_code: str) -> ContractFeatures:
        """
        Extract features from Solidity source code.
        
        Args:
            source_code: Solidity source code string
            
        Returns:
            ContractFeatures object
        """
        features = ContractFeatures()
        
        # Basic counts
        features.num_functions = len(self.compiled_patterns['function'].findall(source_code))
        features.num_external_functions = len(self.compiled_patterns['external_func'].findall(source_code))
        features.num_payable_functions = len(self.compiled_patterns['payable'].findall(source_code))
        features.num_state_variables = len(self.compiled_patterns['state_var'].findall(source_code))
        features.num_mappings = len(self.compiled_patterns['mapping'].findall(source_code))
        
        # External calls
        features.num_low_level_calls = len(self.compiled_patterns['low_level_call'].findall(source_code))
        features.num_transfer_calls = len(self.compiled_patterns['transfer'].findall(source_code))
        features.num_send_calls = len(self.compiled_patterns['send'].findall(source_code))
        features.num_external_calls = (
            features.num_low_level_calls + 
            features.num_transfer_calls + 
            features.num_send_calls +
            len(self.compiled_patterns['external_call'].findall(source_code))
        )
        
        # Fallback/receive
        features.has_fallback = bool(self.compiled_patterns['fallback'].search(source_code))
        features.has_receive = bool(self.compiled_patterns['receive'].search(source_code))
        
        # Protection patterns
        features.has_reentrancy_guard = bool(self.compiled_patterns['reentrancy_guard'].search(source_code))
        features.has_nonreentrant_modifier = 'nonReentrant' in source_code
        features.has_mutex_lock = bool(self.compiled_patterns['mutex'].search(source_code))
        
        # Token patterns
        features.has_erc20_interaction = bool(self.compiled_patterns['erc20'].search(source_code))
        features.has_erc721_interaction = bool(self.compiled_patterns['erc721'].search(source_code))
        features.has_erc777_interaction = bool(self.compiled_patterns['erc777'].search(source_code))
        features.has_flash_loan_callback = bool(self.compiled_patterns['flash_loan'].search(source_code))
        
        # Control flow
        features.num_loops = len(self.compiled_patterns['loop'].findall(source_code))
        features.num_conditionals = len(self.compiled_patterns['conditional'].findall(source_code))
        
        # Analyze CEI pattern and state write after call
        features.state_write_after_call = self._count_state_write_after_call(source_code)
        features.uses_checks_effects_interactions = features.state_write_after_call == 0 and features.num_external_calls > 0
        
        # Calculate risk score
        features.risk_score = self._calculate_risk_score(features)
        features.vulnerability_indicators = self._get_vulnerability_indicators(features)
        
        return features
    
    def extract_from_bytecode(self, bytecode: str) -> ContractFeatures:
        """
        Extract features from EVM bytecode.
        
        Args:
            bytecode: Hex-encoded bytecode
            
        Returns:
            ContractFeatures object
        """
        features = ContractFeatures()
        
        # Clean bytecode
        if bytecode.startswith('0x'):
            bytecode = bytecode[2:]
        bytecode = bytecode.lower()
        
        features.bytecode_length = len(bytecode) // 2  # Bytes
        
        # Count opcodes
        features.num_call_opcodes = (
            bytecode.count(self.OPCODES['CALL']) +
            bytecode.count(self.OPCODES['CALLCODE']) +
            bytecode.count(self.OPCODES['DELEGATECALL']) +
            bytecode.count(self.OPCODES['STATICCALL'])
        )
        features.num_sstore_opcodes = bytecode.count(self.OPCODES['SSTORE'])
        features.num_sload_opcodes = bytecode.count(self.OPCODES['SLOAD'])
        
        # Calculate distance between CALL and SSTORE
        features.call_sstore_distance = self._calculate_call_sstore_distance(bytecode)
        
        # Risk indicators from bytecode
        if features.num_call_opcodes > 0 and features.num_sstore_opcodes > 0:
            if features.call_sstore_distance < 20:  # SSTORE close after CALL
                features.vulnerability_indicators.append("SSTORE_AFTER_CALL")
        
        features.risk_score = self._calculate_bytecode_risk_score(features)
        
        return features
    
    def extract_from_file(self, file_path: Path) -> ContractFeatures:
        """Extract features from a contract file."""
        with open(file_path, 'r') as f:
            source_code = f.read()
        return self.extract_from_source(source_code)
    
    def _count_state_write_after_call(self, source_code: str) -> int:
        """
        Count instances where state is written after external call.
        This is a key reentrancy indicator.
        """
        count = 0
        
        # Find all functions
        function_pattern = r'function\s+\w+[^{]*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}'
        functions = re.findall(function_pattern, source_code, re.DOTALL)
        
        for func_body in functions:
            # Find external calls
            call_matches = list(self.compiled_patterns['low_level_call'].finditer(func_body))
            
            for call_match in call_matches:
                call_pos = call_match.start()
                
                # Check for state writes after the call
                after_call = func_body[call_pos:]
                state_writes = self.compiled_patterns['state_write'].findall(after_call)
                
                if state_writes:
                    count += 1
        
        return count
    
    def _calculate_call_sstore_distance(self, bytecode: str) -> int:
        """Calculate minimum distance between CALL and SSTORE opcodes."""
        call_positions = []
        sstore_positions = []
        
        for i in range(0, len(bytecode) - 1, 2):
            opcode = bytecode[i:i+2]
            if opcode in [self.OPCODES['CALL'], self.OPCODES['DELEGATECALL']]:
                call_positions.append(i)
            elif opcode == self.OPCODES['SSTORE']:
                sstore_positions.append(i)
        
        if not call_positions or not sstore_positions:
            return 999  # No pattern found
        
        min_distance = 999
        for call_pos in call_positions:
            for sstore_pos in sstore_positions:
                if sstore_pos > call_pos:
                    distance = (sstore_pos - call_pos) // 2
                    min_distance = min(min_distance, distance)
        
        return min_distance
    
    def _calculate_risk_score(self, features: ContractFeatures) -> float:
        """
        Calculate overall risk score based on features.
        
        Returns:
            Risk score between 0.0 and 1.0
        """
        score = 0.0
        
        # High risk factors
        if features.num_low_level_calls > 0:
            score += 0.2
        if features.state_write_after_call > 0:
            score += 0.3
        if features.has_fallback or features.has_receive:
            score += 0.1
        if features.has_erc777_interaction:
            score += 0.15
        if features.has_flash_loan_callback:
            score += 0.1
        
        # Mitigating factors
        if features.has_reentrancy_guard:
            score -= 0.3
        if features.has_nonreentrant_modifier:
            score -= 0.25
        if features.uses_checks_effects_interactions:
            score -= 0.2
        
        # Complexity factors
        if features.num_external_calls > 3:
            score += 0.1
        if features.num_loops > 2:
            score += 0.05
        
        return max(0.0, min(1.0, score))
    
    def _calculate_bytecode_risk_score(self, features: ContractFeatures) -> float:
        """Calculate risk score from bytecode features."""
        score = 0.0
        
        if features.num_call_opcodes > 0:
            score += 0.2
        
        if features.call_sstore_distance < 10:
            score += 0.4
        elif features.call_sstore_distance < 20:
            score += 0.2
        
        if features.num_sstore_opcodes > features.num_sload_opcodes:
            score += 0.1
        
        return max(0.0, min(1.0, score))
    
    def _get_vulnerability_indicators(self, features: ContractFeatures) -> List[str]:
        """Get list of vulnerability indicators."""
        indicators = []
        
        if features.state_write_after_call > 0:
            indicators.append("STATE_WRITE_AFTER_EXTERNAL_CALL")
        
        if features.num_low_level_calls > 0 and not features.has_reentrancy_guard:
            indicators.append("UNPROTECTED_LOW_LEVEL_CALL")
        
        if features.has_erc777_interaction:
            indicators.append("ERC777_CALLBACK_RISK")
        
        if features.has_flash_loan_callback:
            indicators.append("FLASH_LOAN_CALLBACK_RISK")
        
        if features.has_fallback and features.num_external_calls > 0:
            indicators.append("FALLBACK_WITH_EXTERNAL_CALLS")
        
        if not features.uses_checks_effects_interactions and features.num_external_calls > 0:
            indicators.append("CEI_PATTERN_NOT_FOLLOWED")
        
        return indicators
    
    def to_vector(self, features: ContractFeatures) -> List[float]:
        """
        Convert features to a numerical vector for ML models.
        
        Args:
            features: ContractFeatures object
            
        Returns:
            List of float values
        """
        return [
            float(features.num_functions),
            float(features.num_external_functions),
            float(features.num_payable_functions),
            float(features.num_state_variables),
            float(features.num_mappings),
            float(features.num_external_calls),
            float(features.num_low_level_calls),
            float(features.num_transfer_calls),
            float(features.num_send_calls),
            float(features.has_fallback),
            float(features.has_receive),
            float(features.state_write_after_call),
            float(features.has_reentrancy_guard),
            float(features.has_nonreentrant_modifier),
            float(features.has_mutex_lock),
            float(features.uses_checks_effects_interactions),
            float(features.has_erc20_interaction),
            float(features.has_erc721_interaction),
            float(features.has_erc777_interaction),
            float(features.has_flash_loan_callback),
            float(features.num_loops),
            float(features.num_conditionals),
            float(features.bytecode_length),
            float(features.num_call_opcodes),
            float(features.num_sstore_opcodes),
            float(features.num_sload_opcodes),
            float(features.call_sstore_distance) if features.call_sstore_distance < 999 else 0.0,
            features.risk_score,
        ]
    
    @staticmethod
    def get_feature_names() -> List[str]:
        """Get names of features in the vector."""
        return [
            "num_functions",
            "num_external_functions",
            "num_payable_functions",
            "num_state_variables",
            "num_mappings",
            "num_external_calls",
            "num_low_level_calls",
            "num_transfer_calls",
            "num_send_calls",
            "has_fallback",
            "has_receive",
            "state_write_after_call",
            "has_reentrancy_guard",
            "has_nonreentrant_modifier",
            "has_mutex_lock",
            "uses_checks_effects_interactions",
            "has_erc20_interaction",
            "has_erc721_interaction",
            "has_erc777_interaction",
            "has_flash_loan_callback",
            "num_loops",
            "num_conditionals",
            "bytecode_length",
            "num_call_opcodes",
            "num_sstore_opcodes",
            "num_sload_opcodes",
            "call_sstore_distance",
            "risk_score",
        ]
