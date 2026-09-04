import pandas as pd


DATASET_PATH = "data/security_samples.csv"


def load_dataset(path="data/security_samples.csv"):

    df = pd.read_csv(path)

    required_columns = {"text", "label"}

    if not required_columns.issubset(df.columns):
        raise ValueError(
            "Dataset must contain 'text' and 'label' columns."
        )

    if df.empty:
        raise ValueError("Dataset is empty.")

    return df