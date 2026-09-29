"""
HexaSentinel — Feature Extractor

Converts a raw network packet window into exactly 80 numerical
features compatible with the HexaSentinel ONNX anomaly classifier.

Expected packet format:

{
"size": int,
"payload_len": int,
"proto": int,
"dst": str,
"dport": int,
"flags": str,
"ts": float
}

The extractor is intentionally stateless and performs no network
communication or disk I/O.
"""

import math
from collections import Counter
from typing import Any, Dict, List

import numpy as np

class FeatureExtractor:
"""
Extract 80 numerical traffic features from a packet window.

The feature layout is kept stable because the ONNX classifier
expects a fixed 80-feature input vector.
"""

FEATURE_COUNT = 80

def extract(self, packets: List[Dict[str, Any]]) -> np.ndarray:
    """
    Convert a packet window into an 80-element float32 vector.

    Args:
        packets:
            List of packet dictionaries.

    Returns:
        np.ndarray:
            Shape (80,), dtype float32.

    Empty or invalid packet windows return an all-zero vector.
    """

    if not packets:
        return self._empty_features()

    normalized_packets = self._normalize_packets(packets)

    if not normalized_packets:
        return self._empty_features()

    sizes = [p["size"] for p in normalized_packets]
    payloads = [p["payload_len"] for p in normalized_packets]
    protocols = [p["proto"] for p in normalized_packets]
    destinations = [p["dst"] for p in normalized_packets]
    destination_ports = [p["dport"] for p in normalized_packets]
    flags = [p["flags"] for p in normalized_packets]
    timestamps = [p["ts"] for p in normalized_packets]

    packet_count = len(normalized_packets)

    # Ensure timestamps are monotonic.
    timestamps.sort()

    duration = max(
        timestamps[-1] - timestamps[0],
        1e-6,
    )

    features: List[float] = []

    # ==============================================================
    # Features 0-9: Flow statistics
    # ==============================================================

    features.extend(
        [
            packet_count / duration,                  # 0  packets/sec
            sum(sizes) / duration,                    # 1  bytes/sec
            float(np.mean(sizes)),                    # 2  mean packet size
            float(np.std(sizes)),                     # 3  packet-size std
            float(np.min(sizes)),                     # 4  minimum packet size
            float(np.max(sizes)),                     # 5  maximum packet size
            float(np.percentile(sizes, 25)),          # 6  Q1 packet size
            float(np.percentile(sizes, 75)),          # 7  Q3 packet size
            float(np.median(sizes)),                  # 8  median packet size
            self._ratio(
                sum(1 for size in sizes if size == 0),
                packet_count,
            ),                                         # 9  zero-size ratio
        ]
    )

    # ==============================================================
    # Features 10-19: Protocol distribution
    # ==============================================================

    protocol_counter = Counter(protocols)

    features.extend(
        [
            self._ratio(protocol_counter.get(6, 0), packet_count),
            # 10 TCP ratio

            self._ratio(protocol_counter.get(17, 0), packet_count),
            # 11 UDP ratio

            self._ratio(protocol_counter.get(1, 0), packet_count),
            # 12 ICMP ratio

            len(protocol_counter) / max(packet_count, 1),
            # 13 protocol diversity

            0.0,  # 14 reserved
            0.0,  # 15 reserved
            0.0,  # 16 reserved
            0.0,  # 17 reserved
            0.0,  # 18 reserved
            0.0,  # 19 reserved
        ]
    )

    # ==============================================================
    # Features 20-29: Connection behaviour
    # ==============================================================

    syn_count = sum(
        1 for flag in flags if "S" in flag and "A" not in flag
    )

    ack_count = sum(
        1 for flag in flags if "A" in flag
    )

    rst_count = sum(
        1 for flag in flags if "R" in flag
    )

    fin_count = sum(
        1 for flag in flags if "F" in flag
    )

    unique_destination_ips = len(set(destinations))
    unique_destination_ports = len(set(destination_ports))

    features.extend(
        [
            float(unique_destination_ips),            # 20 unique dst IPs
            float(unique_destination_ports),           # 21 unique dst ports

            self._ratio(syn_count, packet_count),
            # 22 SYN ratio

            self._ratio(ack_count, packet_count),
            # 23 ACK ratio

            self._ratio(syn_count, max(ack_count, 1)),
            # 24 SYN/ACK ratio

            self._ratio(rst_count, packet_count),
            # 25 RST ratio

            self._ratio(fin_count, packet_count),
            # 26 FIN ratio

            0.0,  # 27 reserved
            0.0,  # 28 reserved
            0.0,  # 29 reserved
        ]
    )

    # ==============================================================
    # Features 30-39: Destination port statistics
    # ==============================================================

    port_counter = Counter(destination_ports)

    total_ports = sum(port_counter.values()) or 1

    entropy = -sum(
        (count / total_ports)
        * math.log2(count / total_ports)
        for count in port_counter.values()
        if count > 0
    )

    well_known_ratio = self._ratio(
        sum(1 for port in destination_ports if port < 1024),
        packet_count,
    )

    registered_ratio = self._ratio(
        sum(
            1
            for port in destination_ports
            if 1024 <= port < 49152
        ),
        packet_count,
    )

    ephemeral_ratio = self._ratio(
        sum(
            1
            for port in destination_ports
            if port >= 49152
        ),
        packet_count,
    )

    features.extend(
        [
            entropy,                                  # 30 port entropy
            well_known_ratio,                         # 31 <1024
            registered_ratio,                         # 32 1024-49151
            ephemeral_ratio,                          # 33 >=49152
            float(unique_destination_ports),          # 34 unique ports
            self._ratio(
                unique_destination_ports,
                packet_count,
            ),                                         # 35 ports/packet
            0.0,                                       # 36 reserved
            0.0,                                       # 37 reserved
            0.0,                                       # 38 reserved
            0.0,                                       # 39 reserved
        ]
    )

    # ==============================================================
    # Features 40-49: Inter-arrival time statistics
    # ==============================================================

    if len(timestamps) > 1:
        inter_arrival_times = np.diff(timestamps)
        inter_arrival_times = np.maximum(
            inter_arrival_times,
            0.0,
        )
    else:
        inter_arrival_times = np.array(
            [0.0],
            dtype=np.float64,
        )

    features.extend(
        [
            float(np.mean(inter_arrival_times)),       # 40 mean IAT
            float(np.std(inter_arrival_times)),        # 41 std IAT
            float(np.min(inter_arrival_times)),        # 42 min IAT
            float(np.max(inter_arrival_times)),        # 43 max IAT
            float(np.percentile(
                inter_arrival_times,
                10,
            )),                                        # 44 P10 IAT
            float(np.percentile(
                inter_arrival_times,
                90,
            )),                                        # 45 P90 IAT
            0.0,                                       # 46 reserved
            0.0,                                       # 47 reserved
            0.0,                                       # 48 reserved
            0.0,                                       # 49 reserved
        ]
    )

    # ==============================================================
    # Features 50-59: Payload statistics
    # ==============================================================

    zero_payload_count = sum(
        1 for payload in payloads if payload == 0
    )

    small_payload_count = sum(
        1 for payload in payloads if payload < 64
    )

    large_payload_count = sum(
        1 for payload in payloads if payload > 1400
    )

    features.extend(
        [
            float(np.mean(payloads)),                 # 50 mean payload
            float(np.std(payloads)),                  # 51 payload std

            self._ratio(
                zero_payload_count,
                packet_count,
            ),                                         # 52 zero payload

            self._ratio(
                small_payload_count,
                packet_count,
            ),                                         # 53 small payload

            self._ratio(
                large_payload_count,
                packet_count,
            ),                                         # 54 large payload

            0.0,  # 55 reserved
            0.0,  # 56 reserved
            0.0,  # 57 reserved
            0.0,  # 58 reserved
            0.0,  # 59 reserved
        ]
    )

    # ==============================================================
    # Features 60-79: Destination diversity
    # ==============================================================

    destination_counts = Counter(destinations)

    unique_destination_count = len(destination_counts)

    destination_ratio = (
        unique_destination_count / max(packet_count, 1)
    )

    max_destination_frequency = (
        max(destination_counts.values())
        if destination_counts
        else 0
    )

    repeated_destination_ratio = (
        max_destination_frequency / max(packet_count, 1)
    )

    features.extend(
        [
            float(unique_destination_count),          # 60 unique dst IPs
            destination_ratio,                        # 61 unique dsts/packet
            repeated_destination_ratio,               # 62 dominant dst ratio
            0.0,                                       # 63 reserved
            0.0,                                       # 64 reserved
            0.0,                                       # 65 reserved
            0.0,                                       # 66 reserved
            0.0,                                       # 67 reserved
            0.0,                                       # 68 reserved
            0.0,                                       # 69 reserved
            0.0,                                       # 70 reserved
            0.0,                                       # 71 reserved
            0.0,                                       # 72 reserved
            0.0,                                       # 73 reserved
            0.0,                                       # 74 reserved
            0.0,                                       # 75 reserved
            0.0,                                       # 76 reserved
            0.0,                                       # 77 reserved
            0.0,                                       # 78 reserved
            0.0,                                       # 79 reserved
        ]
    )

    # ==============================================================
    # Final validation
    # ==============================================================

    if len(features) != self.FEATURE_COUNT:
        raise RuntimeError(
            "HexaSentinel feature extraction produced "
            f"{len(features)} features; expected "
            f"{self.FEATURE_COUNT}."
        )

    result = np.asarray(
        features,
        dtype=np.float32,
    )

    # Prevent NaN / infinity from reaching the ONNX model.
    result = np.nan_to_num(
        result,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )

    return result

# ------------------------------------------------------------------
# Helper methods
# ------------------------------------------------------------------

@staticmethod
def _ratio(numerator: int, denominator: int) -> float:
    """Safely calculate a ratio."""

    if denominator <= 0:
        return 0.0

    return float(numerator) / float(denominator)

@staticmethod
def _empty_features() -> np.ndarray:
    """Return an empty 80-feature vector."""

    return np.zeros(
        FeatureExtractor.FEATURE_COUNT,
        dtype=np.float32,
    )

@staticmethod
def _normalize_packets(
    packets: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Normalize packet dictionaries.

    Malformed packets are skipped rather than crashing the
    complete analysis pipeline.
    """

    normalized = []

    for packet in packets:
        try:
            normalized.append(
                {
                    "size": max(
                        0,
                        int(packet.get("size", 0)),
                    ),

                    "payload_len": max(
                        0,
                        int(packet.get("payload_len", 0)),
                    ),

                    "proto": int(
                        packet.get("proto", 0)
                    ),

                    "dst": str(
                        packet.get("dst", "0.0.0.0")
                    ),

                    "dport": min(
                        max(
                            int(packet.get("dport", 0)),
                            0,
                        ),
                        65535,
                    ),

                    "flags": str(
                        packet.get("flags", "")
                    ).upper(),

                    "ts": float(
                        packet.get("ts", 0.0)
                    ),
                }
            )

        except (
            TypeError,
            ValueError,
            OverflowError,
        ):
            # Ignore malformed packet records.
            continue

    return normalized
