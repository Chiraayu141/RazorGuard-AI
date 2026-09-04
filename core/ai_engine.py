from transformers import pipeline


MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"

_classifier = None


def get_classifier():
    global _classifier

    if _classifier is None:
        _classifier = pipeline(
            "text-classification",
            model=MODEL_NAME
        )

    return _classifier


def analyze_with_ai(text):
    """
    Temporary AI proof-of-concept.

    NOTE:
    The current model performs sentiment classification.
    It is NOT a cybersecurity classifier and must not be
    used directly for security risk scoring.
    """

    classifier = get_classifier()
    result = classifier(text)[0]

    return {
        "model": MODEL_NAME,
        "task": "sentiment-analysis",
        "label": result["label"],
        "confidence": round(result["score"], 4),
    }