"""Batch evaluation and benchmark scoring script for PromptShield."""

import json
import os
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
import numpy as np

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.core.engine import engine


def run_benchmark(dataset_path: Path = None) -> Dict[str, Any]:
    """
    Run evaluation against the dataset and compute key safety metrics.
    """
    if dataset_path is None:
        dataset_path = BASE_DIR / "data" / "eval_dataset.json"

    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset: List[Dict[str, Any]] = json.load(f)

    print(f"\n{'='*70}")
    print(f" PROMPTSHIELD BENCHMARK SUITE - EVALUATING {len(dataset)} TEST CASES")
    print(f"{'='*70}\n")

    latencies = []
    y_true_binary = []  # 0 = clean/benign, 1 = malicious injection
    y_pred_binary = []  # 0 = ALLOW, 1 = BLOCK or REVIEW

    results_table = []

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for item in dataset:
        sample_id = item["id"]
        text = item["text"]
        expected_risk = item["expected_risk"]
        expected_action = item["expected_action"]
        category = item["category"]

        t0 = time.perf_counter()
        resp = engine.inspect(text)
        latency = (time.perf_counter() - t0) * 1000
        latencies.append(latency)

        # Ground truth: prompt is flagged if expected_action is BLOCK or REVIEW
        is_malicious = expected_action in ["BLOCK", "REVIEW"]
        pred_flagged = resp.gate_action in ["BLOCK", "REVIEW"]

        y_true_binary.append(1 if is_malicious else 0)
        y_pred_binary.append(1 if pred_flagged else 0)

        if is_malicious and pred_flagged:
            tp += 1
            status_symbol = "[PASS]"
        elif not is_malicious and not pred_flagged:
            tn += 1
            status_symbol = "[PASS]"
        elif not is_malicious and pred_flagged:
            fp += 1
            status_symbol = "[FALSE POSITIVE]"
        else:
            fn += 1
            status_symbol = "[FALSE NEGATIVE]"

        results_table.append({
            "id": sample_id,
            "category": category,
            "expected_action": expected_action,
            "pred_action": resp.gate_action,
            "risk_score": resp.risk_score,
            "status": status_symbol,
            "labels": ",".join(resp.labels),
            "latency_ms": round(latency, 2),
        })

    total = len(dataset)
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    p50_lat = np.percentile(latencies, 50)
    p95_lat = np.percentile(latencies, 95)
    p99_lat = np.percentile(latencies, 99)

    # Print summary table
    print(f"{'ID':<15} | {'CATEGORY':<18} | {'EXP':<7} | {'PRED':<7} | {'SCORE':<6} | {'STATUS':<16} | {'LATENCY'}")
    print("-" * 85)
    for row in results_table:
        print(f"{row['id']:<15} | {row['category']:<18} | {row['expected_action']:<7} | {row['pred_action']:<7} | {row['risk_score']:<6.2f} | {row['status']:<16} | {row['latency_ms']} ms")

    print("\n" + "=" * 70)
    print(" SUMMARY METRICS")
    print("=" * 70)
    print(f" Total Samples Evaluated: {total}")
    print(f" True Positives  (TP)   : {tp}")
    print(f" True Negatives  (TN)   : {tn}")
    print(f" False Positives (FP)   : {fp}")
    print(f" False Negatives (FN)   : {fn}")
    print("-" * 70)
    print(f" Accuracy               : {accuracy * 100:.2f}%")
    print(f" Precision              : {precision * 100:.2f}%")
    print(f" Recall                 : {recall * 100:.2f}%")
    print(f" F1 Score               : {f1:.4f}")
    print("-" * 70)
    print(f" Latency P50            : {p50_lat:.2f} ms")
    print(f" Latency P95            : {p95_lat:.2f} ms")
    print(f" Latency P99            : {p99_lat:.2f} ms")
    print("=" * 70 + "\n")

    return {
        "total": total,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "latency_p50": p50_lat,
        "latency_p95": p95_lat,
        "latency_p99": p99_lat,
    }


if __name__ == "__main__":
    run_benchmark()
