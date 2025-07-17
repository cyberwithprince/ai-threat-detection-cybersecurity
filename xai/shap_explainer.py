import shap
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
import logging

def explain_packet(packet_data: pd.DataFrame, packet_id: str) -> str:
    """Generate SHAP explanation for a packet"""
    try:
        # Set up logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger(__name__)

        # Set up paths
        base_path = Path(__file__).parent.parent
        model_path = base_path / 'model' / 'xgboost_classifier.pkl'
        explanations_path = base_path / 'logs' / 'explanations'
        explanations_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Loading model from {model_path}")
        model = joblib.load(model_path)

        logger.info("Creating SHAP explainer")
        explainer = shap.TreeExplainer(model)  # Use TreeExplainer for XGBoost

        logger.info("Calculating SHAP values")
        shap_values = explainer(packet_data)

        logger.info("Generating plot")
        plt.figure(figsize=(12, 6))
        shap.plots.waterfall(shap_values[0], show=False)
        
        # Save plot with packet ID
        plot_path = explanations_path / f"packet_{packet_id}_shap.png"
        plt.savefig(plot_path, bbox_inches="tight", dpi=300, facecolor='white')
        plt.close()

        logger.info(f"Saved explanation plot to {plot_path}")
        return str(plot_path)

    except Exception as e:
        logging.error(f"Failed to generate SHAP explanation: {str(e)}")
        raise