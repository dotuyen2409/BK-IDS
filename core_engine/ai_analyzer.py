"""
BK-IDS SOC: Hybrid AI/ML Analyzer Engine
==========================================
Sprint 2 — Phase 1: Machine Learning-based Anomaly Detection

Architecture:
- Isolation Forest for unsupervised outlier detection
- Trained on baseline traffic features (TCP/UDP/ICMP/SYN counts, entropy, unique IPs)
- Hybrid scoring: combines CUSUM + ML for severity escalation
- Model persistence via joblib for warm-start after restart
- Extensible: swap Isolation Forest for other sklearn models via strategy pattern

Features (8-D vector per scan cycle):
    [tcp_count, udp_count, icmp_count, syn_count,
     total_packets, unique_ip_count, ip_entropy, cusum_gn]

Author: BK-IDS SOC Team
Version: 2.0.0 (Sprint 2)
"""

import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("Bk-IDS-ML-Engine")

# ========================================================================
# CONFIGURATION
# ========================================================================
ML_MODEL_DIR = os.environ.get("ML_MODEL_DIR", "/app/storage/ml_models")
ML_MODEL_FILE = os.environ.get("ML_MODEL_FILE", "isolation_forest_v1.joblib")
ML_TRAINING_SAMPLES = int(os.environ.get("ML_TRAINING_SAMPLES", "100"))
ML_CONTAMINATION = float(os.environ.get("ML_CONTAMINATION", "0.05"))
ML_N_ESTIMATORS = int(os.environ.get("ML_N_ESTIMATORS", "100"))
ML_RETRAIN_INTERVAL_SEC = int(os.environ.get("ML_RETRAIN_INTERVAL_SEC", "3600"))
ML_ANOMALY_THRESHOLD = float(os.environ.get("ML_ANOMALY_THRESHOLD", "-0.1"))

# Feature indices for readability
FEATURE_TCP = 0
FEATURE_UDP = 1
FEATURE_ICMP = 2
FEATURE_SYN = 3
FEATURE_TOTAL = 4
FEATURE_UNIQUE_IPS = 5
FEATURE_ENTROPY = 6
FEATURE_CUSUM_GN = 7
FEATURE_NAMES = [
    "tcp_count", "udp_count", "icmp_count", "syn_count",
    "total_packets", "unique_ip_count", "ip_entropy", "cusum_gn",
]


# ========================================================================
# MODEL STRATEGY INTERFACE (Open/Closed Principle)
# ========================================================================
class BaseAnomalyModel:
    """
    Abstract base class for anomaly detection models.
    Implement this interface to add new ML models (e.g., One-Class SVM, Autoencoder).
    """

    def fit(self, X: np.ndarray) -> None:
        """Train the model on baseline data."""
        raise NotImplementedError

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict anomaly labels.

        Returns:
            Array of 1 (normal) or -1 (anomaly) for each sample.
        """
        raise NotImplementedError

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """
        Compute anomaly scores.

        Returns:
            Array of anomaly scores (lower = more anomalous).
        """
        raise NotImplementedError

    def save(self, filepath: str) -> None:
        """Persist model to disk."""
        raise NotImplementedError

    def load(self, filepath: str) -> bool:
        """Load model from disk. Returns True if successful."""
        raise NotImplementedError


class IsolationForestModel(BaseAnomalyModel):
    """
    Isolation Forest anomaly detection model.

    Isolation Forest is ideal for IDS because:
    - Efficient for high-dimensional data (O(n log n))
    - No need for labeled anomaly data (unsupervised)
    - Works well with imbalanced datasets (few attacks vs normal traffic)
    """

    def __init__(
        self,
        n_estimators: int = ML_N_ESTIMATORS,
        contamination: float = ML_CONTAMINATION,
        random_state: int = 42,
    ) -> None:
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self._model: Optional[Any] = None
        self._is_fitted = False
        self._load_sklearn()

    def _load_sklearn(self) -> None:
        """Lazy-load sklearn to handle missing dependency gracefully."""
        try:
            from sklearn.ensemble import IsolationForest
            self._IsolationForest = IsolationForest
        except ImportError:
            logger.warning(
                "[ML] scikit-learn not installed. "
                "Install with: pip install scikit-learn"
            )
            self._IsolationForest = None

    def _create_model(self) -> Any:
        """Create a new Isolation Forest instance."""
        if self._IsolationForest is None:
            raise RuntimeError("scikit-learn not available")
        return self._IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )

    def fit(self, X: np.ndarray) -> None:
        """Train the Isolation Forest on baseline traffic data."""
        if self._IsolationForest is None:
            raise RuntimeError("scikit-learn not available")
        if len(X) < 10:
            logger.warning(f"[ML] Insufficient training data: {len(X)} samples (min 10)")
            return

        self._model = self._create_model()
        self._model.fit(X)
        self._is_fitted = True
        logger.info(f"[ML] Isolation Forest trained on {len(X)} samples")

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict: 1 = normal, -1 = anomaly."""
        if not self._is_fitted or self._model is None:
            return np.ones(len(X))  # Default to normal if not trained
        return self._model.predict(X)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly scores (lower = more anomalous)."""
        if not self._is_fitted or self._model is None:
            return np.zeros(len(X))
        return self._model.score_samples(X)

    def save(self, filepath: str) -> None:
        """Persist model to disk via joblib."""
        if not self._is_fitted or self._model is None:
            return
        try:
            import joblib
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            joblib.dump(self._model, filepath)
            logger.info(f"[ML] Model saved: {filepath}")
        except ImportError:
            logger.warning("[ML] joblib not installed, model not saved")
        except Exception as e:
            logger.error(f"[ML] Save error: {e}")

    def load(self, filepath: str) -> bool:
        """Load model from disk."""
        if not os.path.exists(filepath):
            return False
        try:
            import joblib
            self._model = joblib.load(filepath)
            self._is_fitted = True
            logger.info(f"[ML] Model loaded: {filepath}")
            return True
        except Exception as e:
            logger.error(f"[ML] Load error: {e}")
            return False


# ========================================================================
# FEATURE SCALER (StandardScaler wrapper)
# ========================================================================
class FeatureScaler:
    """
    Standard feature scaler for normalizing traffic features.
    Uses running mean/std to avoid storing all training data.
    """

    def __init__(self) -> None:
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._is_fitted = False

    def fit(self, X: np.ndarray) -> None:
        """Compute mean and std from training data."""
        self._mean = np.mean(X, axis=0)
        self._std = np.std(X, axis=0)
        # Avoid division by zero for constant features
        self._std[self._std == 0] = 1.0
        self._is_fitted = True

    def transform(self, X: np.ndarray) -> np.ndarray:
        """Standardize features: (x - mean) / std."""
        if not self._is_fitted:
            return X
        return (X - self._mean) / self._std

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(X)
        return self.transform(X)

    def save(self, filepath: str) -> None:
        """Save scaler parameters."""
        if not self._is_fitted:
            return
        try:
            import joblib
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            joblib.dump({"mean": self._mean, "std": self._std}, filepath)
        except Exception as e:
            logger.error(f"[ML] Scaler save error: {e}")

    def load(self, filepath: str) -> bool:
        """Load scaler parameters."""
        if not os.path.exists(filepath):
            return False
        try:
            import joblib
            data = joblib.load(filepath)
            self._mean = data["mean"]
            self._std = data["std"]
            self._is_fitted = True
            return True
        except Exception as e:
            logger.error(f"[ML] Scaler load error: {e}")
            return False


# ========================================================================
# HYBRID AI ANALYZER (Main Engine)
# ========================================================================
class HybridAIAnalyzer:
    """
    Hybrid AI analyzer combining CUSUM + Isolation Forest.

    Scoring Logic:
    - CUSUM only alert     → severity = HIGH
    - ML only alert         → severity = MEDIUM
    - CUSUM + ML both alert → severity = CRITICAL (confirmed attack)

    This dual-verification reduces false positives while catching
    attacks that either method alone might miss.
    """

    def __init__(
        self,
        model: Optional[BaseAnomalyModel] = None,
        scaler: Optional[FeatureScaler] = None,
        model_dir: str = ML_MODEL_DIR,
        model_file: str = ML_MODEL_FILE,
    ) -> None:
        self.model_dir = model_dir
        self.model_file = model_file
        self.model_path = os.path.join(model_dir, model_file)
        self.scaler_path = os.path.join(model_dir, "feature_scaler_v1.joblib")

        # Model & Scaler (dependency injection for testability)
        self.model = model or IsolationForestModel()
        self.scaler = scaler or FeatureScaler()

        # Training buffer
        self._training_buffer: List[List[float]] = []
        self._training_lock = threading.Lock()
        self._is_warmup = True
        self._warmup_count = 0
        self._min_training_samples = ML_TRAINING_SAMPLES

        # Metrics
        self._metrics = {
            "total_scored": 0,
            "ml_anomalies": 0,
            "hybrid_critical": 0,
            "model_retrains": 0,
        }
        self._metrics_lock = threading.Lock()

        # Load existing model if available
        self._load_model()

    def _load_model(self) -> None:
        """Load persisted model and scaler from disk."""
        if self.model.load(self.model_path):
            self.scaler.load(self.scaler_path)
            self._is_warmup = False
            logger.info("[ML] Warm start: loaded existing model")

    def _save_model(self) -> None:
        """Persist model and scaler to disk."""
        self.model.save(self.model_path)
        self.scaler.save(self.scaler_path)

    def add_training_sample(
        self,
        tcp: int,
        udp: int,
        icmp: int,
        syn: int,
        total_packets: int,
        unique_ips: int,
        entropy: float,
        cusum_gn: float,
    ) -> None:
        """
        Add a traffic sample to the training buffer.

        Called during warmup phase to collect baseline data.
        Only adds samples when traffic is considered "normal" (low Gn).
        """
        with self._training_lock:
            # Only train on normal traffic (CUSUM below threshold)
            if cusum_gn < 100:
                self._training_buffer.append([
                    float(tcp), float(udp), float(icmp), float(syn),
                    float(total_packets), float(unique_ips),
                    float(entropy), float(cusum_gn),
                ])
                self._warmup_count += 1

            # Auto-train when buffer is full
            if len(self._training_buffer) >= self._min_training_samples:
                self._train_model()

    def _train_model(self) -> None:
        """Train the model on collected baseline data."""
        if len(self._training_buffer) < 10:
            return

        X = np.array(self._training_buffer)

        # Fit scaler and transform
        X_scaled = self.scaler.fit_transform(X)

        # Train model
        self.model.fit(X_scaled)

        # Mark warmup complete
        self._is_warmup = False

        # Persist
        self._save_model()

        with self._metrics_lock:
            self._metrics["model_retrains"] += 1

        logger.info(
            f"[ML] Model trained: {len(self._training_buffer)} samples, "
            f"features={X.shape[1]}"
        )

        # Clear buffer to free memory (keep last 20% for incremental learning)
        keep_count = max(10, len(self._training_buffer) // 5)
        self._training_buffer = self._training_buffer[-keep_count:]

    def analyze(
        self,
        tcp: int,
        udp: int,
        icmp: int,
        syn: int,
        total_packets: int,
        unique_ips: int,
        entropy: float,
        cusum_gn: float,
        cusum_alert: bool = False,
    ) -> Dict[str, Any]:
        """
        Analyze a traffic sample using hybrid CUSUM + ML scoring.

        Args:
            tcp: TCP packet count in scan interval.
            udp: UDP packet count.
            icmp: ICMP packet count.
            syn: SYN packet count.
            total_packets: Total packet count.
            unique_ips: Number of unique source IPs.
            entropy: IP entropy value.
            cusum_gn: Current CUSUM Gn score.
            cusum_alert: Whether CUSUM has flagged this as anomalous.

        Returns:
            Analysis result dictionary:
            {
                "ml_anomaly": bool,       # Isolation Forest detected anomaly
                "ml_score": float,        # Raw anomaly score (lower = more anomalous)
                "hybrid_severity": str,   # LOW / MEDIUM / HIGH / CRITICAL
                "confidence": float,      # 0.0 - 1.0 confidence level
                "reason": str,            # Human-readable explanation
            }
        """
        result = {
            "ml_anomaly": False,
            "ml_score": 0.0,
            "hybrid_severity": "LOW",
            "confidence": 0.0,
            "reason": "Normal traffic",
        }

        # If still in warmup, just collect data
        if self._is_warmup:
            self.add_training_sample(
                tcp, udp, icmp, syn, total_packets, unique_ips, entropy, cusum_gn
            )
            result["reason"] = f"Warmup phase ({self._warmup_count}/{self._min_training_samples})"
            return result

        # Build feature vector
        features = np.array([[
            float(tcp), float(udp), float(icmp), float(syn),
            float(total_packets), float(unique_ips),
            float(entropy), float(cusum_gn),
        ]])

        try:
            # Scale features
            features_scaled = self.scaler.transform(features)

            # Get ML prediction and score
            prediction = self.model.predict(features_scaled)
            score = self.model.score_samples(features_scaled)[0]

            ml_anomaly = prediction[0] == -1

            result["ml_anomaly"] = ml_anomaly
            result["ml_score"] = round(float(score), 4)

            with self._metrics_lock:
                self._metrics["total_scored"] += 1
                if ml_anomaly:
                    self._metrics["ml_anomalies"] += 1

            # ==================================================================
            # HYBRID SCORING LOGIC (CUSUM + ML)
            # ==================================================================
            if cusum_alert and ml_anomaly:
                # Both systems agree → CRITICAL
                result["hybrid_severity"] = "CRITICAL"
                result["confidence"] = 0.95
                result["reason"] = (
                    f"CONFIRMED ATTACK: CUSUM (Gn={cusum_gn:.1f}) + "
                    f"ML (score={score:.4f}) both anomalous"
                )
                with self._metrics_lock:
                    self._metrics["hybrid_critical"] += 1

            elif cusum_alert and not ml_anomaly:
                # CUSUM only → HIGH (possible new attack pattern)
                result["hybrid_severity"] = "HIGH"
                result["confidence"] = 0.7
                result["reason"] = (
                    f"CUSUM alert (Gn={cusum_gn:.1f}) but ML considers normal "
                    f"(score={score:.4f}) — possible new attack pattern"
                )

            elif not cusum_alert and ml_anomaly:
                # ML only → MEDIUM (subtle anomaly CUSUM missed)
                result["hybrid_severity"] = "MEDIUM"
                result["confidence"] = 0.6
                result["reason"] = (
                    f"ML detected subtle anomaly (score={score:.4f}) "
                    f"below CUSUM threshold (Gn={cusum_gn:.1f})"
                )

            else:
                # Neither → LOW
                result["hybrid_severity"] = "LOW"
                result["confidence"] = 0.9
                result["reason"] = "Normal traffic pattern"

        except Exception as e:
            logger.error(f"[ML] Analysis error: {e}")
            result["reason"] = f"ML error: {str(e)}"

        return result

    def get_metrics(self) -> Dict[str, Any]:
        """Return current ML engine metrics."""
        with self._metrics_lock:
            metrics = self._metrics.copy()
        metrics["is_warmup"] = self._is_warmup
        metrics["training_buffer_size"] = len(self._training_buffer)
        return metrics

    def force_retrain(self) -> bool:
        """Force model retraining (e.g., after configuration change)."""
        with self._training_lock:
            if len(self._training_buffer) >= 10:
                self._train_model()
                return True
        return False


# ========================================================================
# SINGLETON INSTANCE
# ========================================================================
_ai_analyzer_singleton: Optional[HybridAIAnalyzer] = None


def get_ai_analyzer() -> HybridAIAnalyzer:
    """
    Get or create the singleton AI analyzer instance.

    Returns:
        HybridAIAnalyzer instance.
    """
    global _ai_analyzer_singleton
    if _ai_analyzer_singleton is None:
        _ai_analyzer_singleton = HybridAIAnalyzer()
    return _ai_analyzer_singleton


def analyze_traffic(
    tcp: int,
    udp: int,
    icmp: int,
    syn: int,
    total_packets: int,
    unique_ips: int,
    entropy: float,
    cusum_gn: float,
    cusum_alert: bool = False,
) -> Dict[str, Any]:
    """
    Convenience function for one-shot traffic analysis.

    This is the main entry point called from sensor_ids.py analyzer_worker.

    Returns:
        Analysis result dict with ml_anomaly, hybrid_severity, confidence, reason.
    """
    analyzer = get_ai_analyzer()
    return analyzer.analyze(
        tcp=tcp, udp=udp, icmp=icmp, syn=syn,
        total_packets=total_packets, unique_ips=unique_ips,
        entropy=entropy, cusum_gn=cusum_gn, cusum_alert=cusum_alert,
    )
