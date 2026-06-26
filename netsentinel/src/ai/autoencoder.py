"""Deep autoencoder for unsupervised anomaly detection."""

import torch
import torch.nn as nn
import numpy as np
from typing import Tuple, Optional


class AnomalyAutoencoder(nn.Module):
    """
    Deep autoencoder for unsupervised anomaly detection.
    Architecture: 128 → 64 → 32 → 16 → 32 → 64 → 128 (symmetric)
    Input: normalized feature vector (dim=128)
    Output: reconstruction error used as anomaly score

    The encoder compresses to a 16-dim bottleneck, forcing the model
    to learn only the most salient normal patterns. Anomalies with
    unusual feature combinations will have high reconstruction error.
    """

    def __init__(self, input_dim: int = 128):
        super().__init__()
        self.input_dim = input_dim

        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.15),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.2),
        )

        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.15),
            nn.Linear(64, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass: encode then decode."""
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def anomaly_score(self, x: torch.Tensor) -> np.ndarray:
        """
        Compute per-sample MSE reconstruction error.
        Returns numpy array of scores (higher = more anomalous).
        """
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            mse = torch.mean((x - reconstructed) ** 2, dim=1).cpu().numpy()
        return mse

    def get_latent(self, x: torch.Tensor) -> np.ndarray:
        """Extract bottleneck (latent) representations."""
        self.eval()
        with torch.no_grad():
            latent = self.encoder(x).cpu().numpy()
        return latent

    def save(self, path: str):
        """Save model weights."""
        torch.save(self.state_dict(), path)

    def load(self, path: str):
        """Load model weights."""
        self.load_state_dict(torch.load(path, map_location="cpu"))
        self.eval()

    @classmethod
    def create_and_train(
        cls,
        train_data: np.ndarray,
        val_data: Optional[np.ndarray] = None,
        input_dim: int = 128,
        epochs: int = 50,
        batch_size: int = 64,
        learning_rate: float = 1e-3,
        device: str = "cpu",
        verbose: bool = True,
    ) -> Tuple["AnomalyAutoencoder", list]:
        """
        Factory method: create, train, and return model + loss history.
        """
        model = cls(input_dim=input_dim)
        model.to(device)

        optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
            optimizer, T_max=epochs
        )
        criterion = nn.MSELoss()

        dataset = torch.utils.data.TensorDataset(
            torch.from_numpy(train_data).float()
        )
        loader = torch.utils.data.DataLoader(
            dataset, batch_size=batch_size, shuffle=True
        )

        history = []

        for epoch in range(epochs):
            model.train()
            epoch_loss = 0.0
            num_batches = 0

            for batch in loader:
                x = batch[0].to(device)
                optimizer.zero_grad()
                reconstructed = model(x)
                loss = criterion(reconstructed, x)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            scheduler.step()
            avg_loss = epoch_loss / max(num_batches, 1)
            history.append(avg_loss)

            if verbose and (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.6f}")

        model.eval()
        return model, history