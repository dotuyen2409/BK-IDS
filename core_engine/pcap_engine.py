"""
BK-IDS SOC: PCAP Forensics Capture Module
===========================================
Captures network traffic to PCAP files when anomalies are detected.
Uses tcpdump for reliable packet capture with automatic rotation.

Features:
- Triggered capture on anomaly detection (CUSUM threshold breach)
- Automatic 60-second capture window
- Organized storage with timestamp and alert_id in filename
- Disk space management (auto-cleanup old PCAPs)
- Kafka event notification for captured files
"""

import logging
import os
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

logger = logging.getLogger("Bk-IDS-PcapEngine")

# ========================================================================
# CONFIGURATION
# ========================================================================
PCAP_STORAGE_DIR = os.environ.get("PCAP_STORAGE_DIR", "/app/storage/pcaps")
PCAP_CAPTURE_DURATION = int(os.environ.get("PCAP_CAPTURE_DURATION", "60"))
PCAP_MAX_FILE_SIZE_MB = int(os.environ.get("PCAP_CAPTURE_MAX_SIZE_MB", "100"))
PCAP_RETENTION_DAYS = int(os.environ.get("PCAP_RETENTION_DAYS", "7"))
PCAP_INTERFACE = os.environ.get("PCAP_INTERFACE", "ens33")
PCAP_SNAPLEN = int(os.environ.get("PCAP_SNAPLEN", "65535"))
PCAP_MAX_FILES = int(os.environ.get("PCAP_MAX_FILES", "1000"))


class PcapCaptureEngine:
    """
    PCAP capture engine for forensic evidence collection.

    Manages triggered packet captures, storage lifecycle,
    and integration with the Kafka alert pipeline.
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        interface: Optional[str] = None,
        capture_duration: Optional[int] = None,
    ) -> None:
        self.storage_dir = storage_dir or PCAP_STORAGE_DIR
        self.interface = interface or PCAP_INTERFACE
        self.capture_duration = capture_duration or PCAP_CAPTURE_DURATION
        self._active_captures: Dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()
        self._ensure_storage_dir()

    def _ensure_storage_dir(self) -> None:
        """Create storage directory if it doesn't exist."""
        try:
            os.makedirs(self.storage_dir, exist_ok=True)
            # Create subdirectories for organization
            os.makedirs(os.path.join(self.storage_dir, "anomaly"), exist_ok=True)
            os.makedirs(os.path.join(self.storage_dir, "signature"), exist_ok=True)
            os.makedirs(os.path.join(self.storage_dir, "manual"), exist_ok=True)
            logger.info(f"[PCAP] Storage directory ready: {self.storage_dir}")
        except OSError as e:
            logger.error(f"[PCAP] Cannot create storage directory: {e}")

    def _generate_filename(
        self,
        alert_id: str,
        attack_type: str,
        src_ip: str,
        category: str = "anomaly",
    ) -> str:
        """
        Generate a descriptive PCAP filename.

        Format: {category}/{timestamp}_{alert_id}_{attack_type}_{src_ip}.pcap

        Args:
            alert_id: Unique alert identifier.
            attack_type: Type of attack detected.
            src_ip: Source IP address.
            alert_id: Alert ID for correlation.
            category: Subdirectory category (anomaly/signature/manual).

        Returns:
            Full path to the PCAP file.
        """
        tz_vn = timezone(timedelta(hours=7))
        timestamp = datetime.now(tz_vn).strftime("%Y%m%d_%H%M%S")

        # Sanitize filename components
        safe_attack = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in attack_type[:30]
        )
        safe_src_ip = src_ip.replace(".", "_").replace(":", "_")
        safe_alert_id = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in str(alert_id)[:20]
        )

        filename = f"{timestamp}_{safe_alert_id}_{safe_attack}_{safe_src_ip}.pcap"
        filepath = os.path.join(self.storage_dir, category, filename)

        return filepath

    def start_capture(
        self,
        alert_id: str,
        attack_type: str,
        src_ip: str,
        category: str = "anomaly",
        duration: Optional[int] = None,
        bpf_filter: Optional[str] = None,
    ) -> Optional[str]:
        """
        Start a triggered PCAP capture.

        Args:
            alert_id: Alert identifier for correlation.
            attack_type: Detected attack type.
            src_ip: Source IP to filter (optional).
            category: Storage category subdirectory.
            duration: Capture duration in seconds (default: PCAP_CAPTURE_DURATION).
            bpf_filter: Additional BPF filter string.

        Returns:
            File path if capture started successfully, None otherwise.
        """
        filepath = self._generate_filename(alert_id, attack_type, src_ip, category)
        capture_time = duration or self.capture_duration

        # Build tcpdump command
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-w", filepath,
            "-s", str(PCAP_SNAPLEN),
            "-c", "0",  # No packet limit, use duration
            "-Z", "root",
        ]

        # Add BPF filter if specified
        if bpf_filter:
            cmd.extend(bpf_filter.split())
        elif src_ip and src_ip not in ("Unknown", "No_Traffic", "Spoofed_IPs_Pool"):
            cmd.extend(["host", src_ip])

        try:
            # Start tcpdump process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,  # Create new process group for clean termination
            )

            with self._lock:
                self._active_captures[alert_id] = process

            logger.info(
                f"[PCAP] Capture started: {filepath} "
                f"(duration={capture_time}s, alert_id={alert_id})"
            )

            # Schedule automatic stop after duration
            timer = threading.Timer(
                capture_time,
                self._stop_capture,
                args=[alert_id],
            )
            timer.daemon = True
            timer.start()

            return filepath

        except FileNotFoundError:
            logger.error("[PCAP] tcpdump not found. Is it installed?")
            return None
        except Exception as e:
            logger.error(f"[PCAP] Failed to start capture: {e}")
            return None

    def _stop_capture(self, alert_id: str) -> None:
        """
        Stop a running PCAP capture by alert_id.

        Args:
            alert_id: The alert identifier for the capture to stop.
        """
        with self._lock:
            process = self._active_captures.pop(alert_id, None)

        if process is None:
            return

        try:
            # Send SIGTERM to the process group
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
            logger.info(f"[PCAP] Capture stopped: alert_id={alert_id}")
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                logger.warning(f"[PCAP] Capture force-killed: alert_id={alert_id}")
            except Exception:
                pass
        except Exception as e:
            logger.error(f"[PCAP] Error stopping capture: {e}")

    def stop_all_captures(self) -> None:
        """Stop all active PCAP captures."""
        with self._lock:
            alert_ids = list(self._active_captures.keys())

        for alert_id in alert_ids:
            self._stop_capture(alert_id)

        logger.info(f"[PCAP] All captures stopped ({len(alert_ids)} total)")

    def get_capture_status(self, alert_id: str) -> Dict[str, Any]:
        """
        Get status of a specific capture.

        Returns:
            Dictionary with capture status information.
        """
        with self._lock:
            process = self._active_captures.get(alert_id)

        if process is None:
            return {"alert_id": alert_id, "status": "not_found"}

        if process.poll() is None:
            return {"alert_id": alert_id, "status": "running", "pid": process.pid}
        else:
            return {
                "alert_id": alert_id,
                "status": "completed",
                "return_code": process.returncode,
            }

    def cleanup_old_files(self) -> int:
        """
        Remove PCAP files older than retention period.

        Returns:
            Number of files removed.
        """
        removed = 0
        cutoff_time = time.time() - (PCAP_RETENTION_DAYS * 86400)

        try:
            for root, dirs, files in os.walk(self.storage_dir):
                for filename in files:
                    if not filename.endswith(".pcap"):
                        continue
                    filepath = os.path.join(root, filename)
                    try:
                        file_mtime = os.path.getmtime(filepath)
                        if file_mtime < cutoff_time:
                            os.remove(filepath)
                            removed += 1
                    except OSError:
                        pass

            if removed > 0:
                logger.info(f"[PCAP] Cleaned up {removed} old files")

            # Also enforce max file count
            all_pcaps = []
            for root, dirs, files in os.walk(self.storage_dir):
                for f in files:
                    if f.endswith(".pcap"):
                        fp = os.path.join(root, f)
                        all_pcaps.append((fp, os.path.getmtime(fp)))

            if len(all_pcaps) > PCAP_MAX_FILES:
                all_pcaps.sort(key=lambda x: x[1])  # Oldest first
                for fp, mt in all_pcaps[: len(all_pcaps) - PCAP_MAX_FILES]:
                    try:
                        os.remove(fp)
                        removed += 1
                    except OSError:
                        pass

        except Exception as e:
            logger.error(f"[PCAP] Cleanup error: {e}")

        return removed

    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage directory statistics.

        Returns:
            Dictionary with storage usage information.
        """
        stats = {
            "storage_dir": self.storage_dir,
            "total_files": 0,
            "total_size_mb": 0,
            "categories": {},
        }

        try:
            for root, dirs, files in os.walk(self.storage_dir):
                category = os.path.basename(root)
                cat_files = [f for f in files if f.endswith(".pcap")]
                cat_size = sum(
                    os.path.getsize(os.path.join(root, f)) for f in cat_files
                )
                stats["categories"][category] = {
                    "file_count": len(cat_files),
                    "size_mb": round(cat_size / (1024 * 1024), 2),
                }
                stats["total_files"] += len(cat_files)
                stats["total_size_mb"] += cat_size

            stats["total_size_mb"] = round(stats["total_size_mb"] / (1024 * 1024), 2)
        except Exception as e:
            logger.error(f"[PCAP] Stats error: {e}")

        return stats


# ========================================================================
# SINGLETON INSTANCE
# ========================================================================
_pcap_engine_singleton: Optional[PcapCaptureEngine] = None


def get_pcap_engine() -> PcapCaptureEngine:
    """
    Get or create the singleton PCAP engine instance.

    Returns:
        PcapCaptureEngine instance.
    """
    global _pcap_engine_singleton
    if _pcap_engine_singleton is None:
        _pcap_engine_singleton = PcapCaptureEngine()
    return _pcap_engine_singleton


def trigger_anomaly_pcap(
    alert_id: str,
    attack_type: str,
    src_ip: str,
    gn_score: float,
) -> Optional[str]:
    """
    Trigger a PCAP capture for an anomaly detection event.

    This is the main entry point called from sensor_ids.py when
    CUSUM detects an anomaly above the threshold.

    Args:
        alert_id: Unique alert identifier.
        attack_type: Detected attack type.
        src_ip: Source IP address.
        gn_score: CUSUM Gn score.

    Returns:
        PCAP file path if capture started, None otherwise.
    """
    engine = get_pcap_engine()

    # Only capture for significant events
    if gn_score < 200:
        logger.debug(f"[PCAP] Skipping capture for low-score event: gn={gn_score}")
        return None

    filepath = engine.start_capture(
        alert_id=alert_id,
        attack_type=attack_type,
        src_ip=src_ip,
        category="anomaly",
    )

    if filepath:
        logger.info(
            f"[PCAP] Anomaly capture triggered: {filepath} "
            f"(attack={attack_type}, src={src_ip}, gn={gn_score})"
        )

    return filepath


def trigger_signature_pcap(
    alert_id: str,
    sig_name: str,
    src_ip: str,
    dst_ip: str,
) -> Optional[str]:
    """
    Trigger a PCAP capture for a signature-based detection event.

    This is the main entry point called from inline_ips.py when
    Snort detects a signature match with DROP action.

    Args:
        alert_id: Unique alert identifier.
        sig_name: Snort signature name.
        src_ip: Source IP address.
        dst_ip: Destination IP address.

    Returns:
        PCAP file path if capture started, None otherwise.
    """
    engine = get_pcap_engine()

    filepath = engine.start_capture(
        alert_id=alert_id,
        attack_type=sig_name,
        src_ip=src_ip,
        category="signature",
        bpf_filter=f"host {src_ip} and host {dst_ip}" if dst_ip != "Unknown" else None,
    )

    if filepath:
        logger.info(
            f"[PCAP] Signature capture triggered: {filepath} "
            f"(sig={sig_name}, src={src_ip})"
        )

    return filepath
