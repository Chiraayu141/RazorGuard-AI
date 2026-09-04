import pandas as pd

from core.security_classifier import SecurityClassifier


DATASET_PATH = "data/test_samples.csv"


def evaluate_classifier(dataset_path=DATASET_PATH):
    """
    Evaluate the SecurityClassifier on the unseen test dataset.

    Returns:
        dict containing accuracy, precision, recall, F1 score,
        confusion matrix, and per-class metrics.
    """

    df = pd.read_csv(dataset_path)

    required_columns = {"text", "label"}

    if not required_columns.issubset(df.columns):
        raise ValueError(
            "Dataset must contain 'text' and 'label' columns."
        )

    if df.empty:
        raise ValueError("Dataset is empty.")

    classifier = SecurityClassifier()

    labels = ["SAFE", "SUSPICIOUS", "MALICIOUS"]

    confusion_matrix = {
        actual: {predicted: 0 for predicted in labels}
        for actual in labels
    }

    for _, row in df.iterrows():
        actual = row["label"]
        result = classifier.predict(row["text"])
        predicted = result["label"]

        if actual in labels and predicted in labels:
            confusion_matrix[actual][predicted] += 1

    total = len(df)
    correct = sum(
        confusion_matrix[label][label]
        for label in labels
    )

    accuracy = correct / total if total else 0.0

    class_metrics = {}

    for label in labels:
        true_positive = confusion_matrix[label][label]

        false_positive = sum(
            confusion_matrix[other][label]
            for other in labels
            if other != label
        )

        false_negative = sum(
            confusion_matrix[label][other]
            for other in labels
            if other != label
        )

        precision = (
            true_positive / (true_positive + false_positive)
            if (true_positive + false_positive)
            else 0.0
        )

        recall = (
            true_positive / (true_positive + false_negative)
            if (true_positive + false_negative)
            else 0.0
        )

        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )

        class_metrics[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    macro_precision = sum(
        metrics["precision"]
        for metrics in class_metrics.values()
    ) / len(labels)

    macro_recall = sum(
        metrics["recall"]
        for metrics in class_metrics.values()
    ) / len(labels)

    macro_f1 = sum(
        metrics["f1"]
        for metrics in class_metrics.values()
    ) / len(labels)

    return {
        "correct": correct,
        "total": total,
        "accuracy": accuracy,
        "precision": macro_precision,
        "recall": macro_recall,
        "f1": macro_f1,
        "class_metrics": class_metrics,
        "confusion_matrix": confusion_matrix,
    }


def print_evaluation_report(results):
    """Print a readable evaluation report."""

    print()
    print("=" * 50)
    print("        RAZORGUARD-AI MODEL EVALUATION")
    print("=" * 50)

    print()
    print("OVERALL METRICS")
    print("-" * 50)

    print(f"Accuracy  : {results['accuracy'] * 100:.2f}%")
    print(f"Precision : {results['precision'] * 100:.2f}%")
    print(f"Recall    : {results['recall'] * 100:.2f}%")
    print(f"F1 Score  : {results['f1'] * 100:.2f}%")

    print()
    print("PER-CLASS METRICS")
    print("-" * 50)

    for label, metrics in results["class_metrics"].items():
        print(f"{label}")
        print(f"  Precision : {metrics['precision'] * 100:.2f}%")
        print(f"  Recall    : {metrics['recall'] * 100:.2f}%")
        print(f"  F1 Score  : {metrics['f1'] * 100:.2f}%")

    print()
    print("CONFUSION MATRIX")
    print("-" * 50)

    labels = ["SAFE", "SUSPICIOUS", "MALICIOUS"]

    print(
        f"{'Actual':<15}"
        f"{'SAFE':<12}"
        f"{'SUSPICIOUS':<15}"
        f"{'MALICIOUS':<12}"
    )

    for actual in labels:
        print(
            f"{actual:<15}"
            f"{results['confusion_matrix'][actual]['SAFE']:<12}"
            f"{results['confusion_matrix'][actual]['SUSPICIOUS']:<15}"
            f"{results['confusion_matrix'][actual]['MALICIOUS']:<12}"
        )

    print()
    print(
        f"Correct : {results['correct']}/{results['total']}"
    )


if __name__ == "__main__":
    results = evaluate_classifier()
    print_evaluation_report(results)