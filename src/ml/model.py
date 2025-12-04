"""
ML Model for Reentrancy Classification

Provides machine learning models for classifying smart contracts
as vulnerable or safe from reentrancy attacks.
"""

import pickle
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
import numpy as np

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import classification_report, confusion_matrix
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


@dataclass
class PredictionResult:
    """Result of a vulnerability prediction."""
    is_vulnerable: bool
    confidence: float
    vulnerability_type: Optional[str] = None
    risk_factors: List[str] = None
    model_used: str = "unknown"


class ReentrancyClassifier:
    """
    Machine learning classifier for reentrancy vulnerability detection.
    
    Supports multiple model types:
    - Random Forest (default)
    - Gradient Boosting
    - Neural Network (if PyTorch available)
    
    Usage:
        classifier = ReentrancyClassifier()
        classifier.train(X_train, y_train)
        result = classifier.predict(features)
    """
    
    def __init__(self, model_type: str = "random_forest"):
        """
        Initialize the classifier.
        
        Args:
            model_type: Type of model to use
                       ("random_forest", "gradient_boosting", "neural_network")
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler() if SKLEARN_AVAILABLE else None
        self.is_trained = False
        self.feature_importance = None
        
        self._init_model()
    
    def _init_model(self):
        """Initialize the ML model based on type."""
        if not SKLEARN_AVAILABLE:
            print("Warning: scikit-learn not available. Using rule-based fallback.")
            return
        
        if self.model_type == "random_forest":
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                class_weight='balanced',
            )
        elif self.model_type == "gradient_boosting":
            self.model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=5,
                learning_rate=0.1,
                random_state=42,
            )
        elif self.model_type == "neural_network" and TORCH_AVAILABLE:
            self.model = ReentrancyNeuralNetwork(input_size=28)
        else:
            # Default to random forest
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
            )
    
    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        validation_split: float = 0.2,
    ) -> Dict[str, Any]:
        """
        Train the classifier on labeled data.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (0 = safe, 1 = vulnerable)
            validation_split: Fraction of data for validation
            
        Returns:
            Training metrics dictionary
        """
        if not SKLEARN_AVAILABLE:
            return {"error": "scikit-learn not available"}
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X_scaled, y, test_size=validation_split, random_state=42, stratify=y
        )
        
        # Train model
        if self.model_type == "neural_network" and TORCH_AVAILABLE:
            metrics = self._train_neural_network(X_train, y_train, X_val, y_val)
        else:
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_val)
            
            metrics = {
                "accuracy": (y_pred == y_val).mean(),
                "classification_report": classification_report(y_val, y_pred, output_dict=True),
                "confusion_matrix": confusion_matrix(y_val, y_pred).tolist(),
            }
            
            # Cross-validation
            cv_scores = cross_val_score(self.model, X_scaled, y, cv=5)
            metrics["cv_mean"] = cv_scores.mean()
            metrics["cv_std"] = cv_scores.std()
            
            # Feature importance
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importance = self.model.feature_importances_
        
        self.is_trained = True
        return metrics
    
    def _train_neural_network(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 100,
    ) -> Dict[str, Any]:
        """Train the neural network model."""
        if not TORCH_AVAILABLE:
            return {"error": "PyTorch not available"}
        
        # Convert to tensors
        X_train_t = torch.FloatTensor(X_train)
        y_train_t = torch.FloatTensor(y_train).unsqueeze(1)
        X_val_t = torch.FloatTensor(X_val)
        y_val_t = torch.FloatTensor(y_val).unsqueeze(1)
        
        # Training
        criterion = nn.BCELoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        
        best_val_loss = float('inf')
        history = {"train_loss": [], "val_loss": []}
        
        for epoch in range(epochs):
            # Training
            self.model.train()
            optimizer.zero_grad()
            outputs = self.model(X_train_t)
            loss = criterion(outputs, y_train_t)
            loss.backward()
            optimizer.step()
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                val_outputs = self.model(X_val_t)
                val_loss = criterion(val_outputs, y_val_t)
            
            history["train_loss"].append(loss.item())
            history["val_loss"].append(val_loss.item())
            
            if val_loss < best_val_loss:
                best_val_loss = val_loss
        
        # Final evaluation
        self.model.eval()
        with torch.no_grad():
            y_pred = (self.model(X_val_t) > 0.5).float().numpy().flatten()
        
        return {
            "accuracy": (y_pred == y_val).mean(),
            "final_train_loss": history["train_loss"][-1],
            "final_val_loss": history["val_loss"][-1],
            "history": history,
        }
    
    def predict(self, features: List[float]) -> PredictionResult:
        """
        Predict vulnerability for a single contract.
        
        Args:
            features: Feature vector from FeatureExtractor
            
        Returns:
            PredictionResult with vulnerability assessment
        """
        if not self.is_trained:
            # Use rule-based fallback
            return self._rule_based_predict(features)
        
        # Scale features
        X = np.array(features).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        
        if self.model_type == "neural_network" and TORCH_AVAILABLE:
            self.model.eval()
            with torch.no_grad():
                X_tensor = torch.FloatTensor(X_scaled)
                prob = self.model(X_tensor).item()
            
            return PredictionResult(
                is_vulnerable=prob > 0.5,
                confidence=prob if prob > 0.5 else 1 - prob,
                model_used="neural_network",
            )
        else:
            prediction = self.model.predict(X_scaled)[0]
            probabilities = self.model.predict_proba(X_scaled)[0]
            
            return PredictionResult(
                is_vulnerable=bool(prediction),
                confidence=float(max(probabilities)),
                model_used=self.model_type,
            )
    
    def _rule_based_predict(self, features: List[float]) -> PredictionResult:
        """
        Rule-based prediction fallback when model not trained.
        
        Uses heuristics based on known vulnerability patterns.
        """
        risk_factors = []
        risk_score = 0.0
        
        # Feature indices (based on FeatureExtractor.to_vector order)
        num_low_level_calls = features[6]
        state_write_after_call = features[11]
        has_reentrancy_guard = features[12]
        has_nonreentrant = features[13]
        has_erc777 = features[18]
        has_flash_loan = features[19]
        
        # Rule-based scoring
        if state_write_after_call > 0:
            risk_score += 0.4
            risk_factors.append("State write after external call")
        
        if num_low_level_calls > 0 and not has_reentrancy_guard and not has_nonreentrant:
            risk_score += 0.3
            risk_factors.append("Unprotected low-level calls")
        
        if has_erc777:
            risk_score += 0.15
            risk_factors.append("ERC777 token interaction")
        
        if has_flash_loan:
            risk_score += 0.1
            risk_factors.append("Flash loan callback")
        
        # Mitigations
        if has_reentrancy_guard or has_nonreentrant:
            risk_score -= 0.3
        
        is_vulnerable = risk_score > 0.3
        
        return PredictionResult(
            is_vulnerable=is_vulnerable,
            confidence=min(0.95, max(0.5, abs(risk_score - 0.3) + 0.5)),
            risk_factors=risk_factors,
            model_used="rule_based",
        )
    
    def save(self, path: str):
        """Save the trained model to disk."""
        if not self.is_trained:
            raise ValueError("Model not trained yet")
        
        data = {
            "model_type": self.model_type,
            "scaler": self.scaler,
            "feature_importance": self.feature_importance,
        }
        
        if self.model_type == "neural_network" and TORCH_AVAILABLE:
            data["model_state"] = self.model.state_dict()
        else:
            data["model"] = self.model
        
        with open(path, 'wb') as f:
            pickle.dump(data, f)
    
    def load(self, path: str):
        """Load a trained model from disk."""
        with open(path, 'rb') as f:
            data = pickle.load(f)
        
        self.model_type = data["model_type"]
        self.scaler = data["scaler"]
        self.feature_importance = data.get("feature_importance")
        
        if self.model_type == "neural_network" and TORCH_AVAILABLE:
            self._init_model()
            self.model.load_state_dict(data["model_state"])
        else:
            self.model = data["model"]
        
        self.is_trained = True
    
    def get_feature_importance(self, feature_names: List[str]) -> List[Tuple[str, float]]:
        """
        Get feature importance rankings.
        
        Args:
            feature_names: Names of features
            
        Returns:
            List of (feature_name, importance) tuples, sorted by importance
        """
        if self.feature_importance is None:
            return []
        
        importance_pairs = list(zip(feature_names, self.feature_importance))
        return sorted(importance_pairs, key=lambda x: x[1], reverse=True)


if TORCH_AVAILABLE:
    class ReentrancyNeuralNetwork(nn.Module):
        """
        Neural network for reentrancy classification.
        
        Architecture:
        - Input layer (28 features)
        - Hidden layer 1 (64 units, ReLU, Dropout)
        - Hidden layer 2 (32 units, ReLU, Dropout)
        - Output layer (1 unit, Sigmoid)
        """
        
        def __init__(self, input_size: int = 28):
            super().__init__()
            
            self.network = nn.Sequential(
                nn.Linear(input_size, 64),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(32, 16),
                nn.ReLU(),
                nn.Linear(16, 1),
                nn.Sigmoid(),
            )
        
        def forward(self, x):
            return self.network(x)
