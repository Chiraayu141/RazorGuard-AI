from collections import Counter

from core.dataset import load_dataset


class SecurityClassifier:

    def __init__(self):
        self.dataset = load_dataset()
        self.keyword_labels = {}
        self.phrase_labels = {}

        self._build_keyword_index()
        self._build_phrase_index()

    def _build_keyword_index(self):
        for _, row in self.dataset.iterrows():

            words = row["text"].lower().split()

            for word in words:

                word = word.strip(".,!?;:\"'")

                if len(word) < 4:
                    continue

                self.keyword_labels.setdefault(
                    word,
                    []
                ).append(row["label"])

    def _build_phrase_index(self):

        phrase_groups = {

            "security_bypass": [
                "disable antivirus",
                "turn off antivirus",
                "turn off the security software",
                "disable security",
                "bypass security",
            ],

            "credential_request": [
                "send me your password",
                "send me your credentials",
                "provide your password",
                "provide your authentication token",
                "enter your login credentials",
            ],
        }

        for category, variants in phrase_groups.items():

            for variant in variants:

                self.phrase_labels[variant] = category

    def predict(self, text):

        text_lower = text.lower()

        # =====================================================
        # Phrase-Level Detection
        # =====================================================

        for phrase in self.phrase_labels:

            if phrase in text_lower:

                category = self.phrase_labels[phrase]

                if category == "security_bypass":

                    return {
                        "label": "SUSPICIOUS",
                        "confidence": 0.90
                    }

                return {
                    "label": "MALICIOUS",
                    "confidence": 0.90
                }

        # =====================================================
        # Word-Level Baseline
        # =====================================================

        words = text_lower.split()

        matched_labels = []

        for word in words:

            word = word.strip(".,!?;:\"'")

            if word in self.keyword_labels:

                matched_labels.extend(
                    self.keyword_labels[word]
                )

        # No known indicators.
        if not matched_labels:

            return {
                "label": "SAFE",
                "confidence": 0.50
            }

        # =====================================================
        # Majority Vote
        # =====================================================

        counts = Counter(matched_labels)

        label, count = counts.most_common(1)[0]

        confidence = count / len(matched_labels)

        return {
            "label": label,
            "confidence": round(confidence, 4)
        }


def evaluate_classifier():

    classifier = SecurityClassifier()

    correct = 0
    total = len(classifier.dataset)

    label_results = {
        "SAFE": {
            "correct": 0,
            "total": 0
        },
        "SUSPICIOUS": {
            "correct": 0,
            "total": 0
        },
        "MALICIOUS": {
            "correct": 0,
            "total": 0
        }
    }

    confusion_matrix = {
        "SAFE": {
            "SAFE": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0
        },
        "SUSPICIOUS": {
            "SAFE": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0
        },
        "MALICIOUS": {
            "SAFE": 0,
            "SUSPICIOUS": 0,
            "MALICIOUS": 0
        }
    }

    for _, row in classifier.dataset.iterrows():

        expected = row["label"]

        result = classifier.predict(row["text"])

        predicted = result["label"]

        if predicted == expected:
            correct += 1

        if expected in label_results:
            label_results[expected]["total"] += 1

            if predicted == expected:
                label_results[expected]["correct"] += 1

        if (
            expected in confusion_matrix
            and predicted in confusion_matrix[expected]
        ):
            confusion_matrix[expected][predicted] += 1

    accuracy = correct / total if total else 0.0

    per_label_accuracy = {}

    for label, values in label_results.items():

        if values["total"] == 0:
            per_label_accuracy[label] = 0.0

        else:
            per_label_accuracy[label] = round(
                values["correct"] / values["total"],
                4
            )

    return {
        "correct": correct,
        "total": total,
        "accuracy": round(accuracy, 4),
        "per_label_accuracy": per_label_accuracy,
        "confusion_matrix": confusion_matrix
    }


def evaluate_test_set():

    classifier = SecurityClassifier()

    test_data = load_dataset(
        "data/test_samples.csv"
    )

    correct = 0
    total = len(test_data)

    results = []

    print("\nUNSEEN TEST SET")
    print("-" * 50)

    for _, row in test_data.iterrows():

        result = classifier.predict(row["text"])

        expected = row["label"]
        predicted = result["label"]

        status = "✓" if predicted == expected else "✗"

        print(
            f"{status} "
            f"Expected: {expected:<10} "
            f"Predicted: {predicted:<10} "
            f"Confidence: {result['confidence']}"
        )

        if predicted == expected:
            correct += 1

        results.append({
            "text": row["text"],
            "expected": expected,
            "predicted": predicted,
            "confidence": result["confidence"],
            "correct": predicted == expected
        })

    accuracy = correct / total if total else 0.0

    print("-" * 50)
    print(f"Correct  : {correct}/{total}")
    print(f"Accuracy : {accuracy:.2%}")

    return {
        "correct": correct,
        "total": total,
        "accuracy": round(accuracy, 4),
        "results": results
    }