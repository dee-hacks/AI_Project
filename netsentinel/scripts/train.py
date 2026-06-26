"""
Offline training script for NetSentinel anomaly detection models.
Generates synthetic training data if no PCAP data is available.

Usage:
    python scripts/train.py --input data/features.npy --epochs 50
    python scripts/train.py --generate-synthetic --samples 10000
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.ai.trainer import Trainer


def generate_synthetic_data(n_samples: int = 10000, input_dim: int = 128) -> np.ndarray:
    """
    Generate synthetic normal traffic features for training.
    Creates multi-modal Gaussian clusters to simulate normal patterns.
    """
    np.random.seed(42)

    # Base normal traffic cluster (HTTP/HTTPS/SSH patterns)
    n_base = n_samples // 2
    base = np.random.randn(n_base, input_dim) * 0.3
    base[:, 0] += 6.0  # TCP protocol
    base[:, 3] += 0.3  # sport ~80/443 range
    base[:, 4] += 0.5  # dport ~80/443 range
    base[:, 5] += 0.4  # pkt_len ~500-1000
    base[:, 6] += 0.5  # TTL ~128

    # Second cluster (DNS/NTP patterns)
    n_dns = n_samples // 4
    dns = np.random.randn(n_dns, input_dim) * 0.2
    dns[:, 0] += 17.0  # UDP protocol
    dns[:, 3] += 0.6  # high sport
    dns[:, 4] -= 0.3  # low dport
    dns[:, 5] -= 0.2  # small packets
    dns[:, 8] += 0.1  # payload entropy

    # Third cluster (internal traffic)
    n_internal = n_samples - n_base - n_dns
    internal = np.random.randn(n_internal, input_dim) * 0.25
    internal[:, 1] += 0.7  # internal IP range
    internal[:, 2] += 0.7

    features = np.vstack([base, dns, internal])
    np.random.shuffle(features)

    # Normalize to [0, 1] roughly
    features = (features - features.min(axis=0)) / (
        features.max(axis=0) - features.min(axis=0) + 1e-8
    )

    return features.astype(np.float32)


def main():
    parser = argparse.ArgumentParser(description="Train NetSentinel AI models")
    parser.add_argument("--input", type=str, help="Path to input features .npy file")
    parser.add_argument(
        "--generate-synthetic", action="store_true", help="Generate synthetic training data"
    )
    parser.add_argument("--samples", type=int, default=10000, help="Number of synthetic samples")
    parser.add_argument("--epochs", type=int, default=50, help="Autoencoder training epochs")
    parser.add_argument("--batch-size", type=int, default=64, help="Training batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument(
        "--output-dir", type=str, default="data/models", help="Output directory for models"
    )

    args = parser.parse_args()

    # Load or generate data
    if args.input and os.path.exists(args.input):
        print(f"Loading features from {args.input}")
        features = np.load(args.input)
    elif args.generate_synthetic:
        print(f"Generating {args.samples} synthetic samples...")
        features = generate_synthetic_data(args.samples)
        os.makedirs("data", exist_ok=True)
        np.save("data/training_features.npy", features)
        print(f"Saved synthetic data to data/training_features.npy")
    else:
        print("No input data specified. Generating synthetic data...")
        features = generate_synthetic_data()
        os.makedirs("data", exist_ok=True)
        np.save("data/training_features.npy", features)

    print(f"Feature matrix shape: {features.shape}")

    # Create trainer
    trainer = Trainer(
        input_dim=features.shape[1],
        ae_epochs=args.epochs,
        ae_batch_size=args.batch_size,
        ae_lr=args.lr,
    )

    # Train
    results = trainer.train(features)

    # Save models
    os.makedirs(args.output_dir, exist_ok=True)
    trainer.save_all(
        ae_path=os.path.join(args.output_dir, "autoencoder.pt"),
        if_path=os.path.join(args.output_dir, "isolation_forest.pkl"),
        ensemble_path=os.path.join(args.output_dir, "ensemble_config.json"),
        normalizer_path=os.path.join(args.output_dir, "normalizer_stats.json"),
    )

    print("\nTraining complete!")
    print(f"  Threshold: {results['threshold']:.6f}")
    print(f"  Validation anomaly rate: {results['val_anomaly_rate']*100:.4f}%")
    print(f"  AE final loss: {results['ae_final_loss']:.6f}")
    print(f"  Models saved to: {args.output_dir}/")


if __name__ == "__main__":
    main()