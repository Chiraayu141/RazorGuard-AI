from core.pipeline import RazorGuardPipeline


def print_report(result):
    print()
    print("=" * 40)
    print("      RAZORGUARD-AI SECURITY REPORT")
    print("=" * 40)

    print()
    print(f"Risk Level : {result['risk_level']}")
    print(f"Risk Score : {result['risk_score']}/100")

    print()
    print("FINDINGS")
    print("-" * 40)

    if result["findings"]:
        for i, finding in enumerate(result["findings"], start=1):
            print(f"{i}. {finding['keyword']}")
            print(f"   Severity : {finding['severity']}")
            print(f"   Type     : {finding['type']}")

            if "category" in finding:
                print(f"   Category : {finding['category']}")

            print()
    else:
        print("No rule-based security findings detected.")

    print("AI CLASSIFICATION")
    print("-" * 40)
    print(f"Label      : {result['classifier']['label']}")
    print(f"Confidence : {result['classifier']['confidence']}")

    print()
    print("SCORE BREAKDOWN")
    print("-" * 40)
    print(f"Pattern Score    : {result['pattern_score']}/100")
    print(f"Classifier Score : {result['classifier_score']}/100")


def main():
    print("=" * 40)
    print("        RAZORGUARD-AI")
    print("=" * 40)

    text = input("\nEnter text to analyze: ")

    if not text.strip():
        print("\nNo text provided.")
        return

    pipeline = RazorGuardPipeline()
    result = pipeline.analyze(text)

    print_report(result)


if __name__ == "__main__":
    main()