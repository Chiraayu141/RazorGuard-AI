import gradio as gr

from core.pipeline import RazorGuardPipeline
from core.history import load_history, clear_history
from core.report import generate_report


pipeline = RazorGuardPipeline()


# =============================================================
# Risk Helpers
# =============================================================

def get_risk_icon(risk_level):
    if risk_level == "CRITICAL":
        return "🔴"
    elif risk_level == "HIGH":
        return "🟠"
    elif risk_level == "MEDIUM":
        return "🟡"
    elif risk_level == "LOW":
        return "🔵"
    else:
        return "🟢"


def get_risk_description(risk_level):
    descriptions = {
        "CRITICAL": "Immediate investigation recommended.",
        "HIGH": "Further investigation recommended.",
        "MEDIUM": "Review the detected indicators carefully.",
        "LOW": "Low-risk indicators detected.",
        "SAFE": "No significant security indicators detected.",
    }

    return descriptions.get(
        risk_level,
        "Review the analysis results.",
    )


# =============================================================
# History
# =============================================================

def format_history():
    history = load_history()

    if not history:
        return (
            "### 📭 No analysis history yet.\n\n"
            "Run an analysis to start building your security history."
        )

    history_text = ""

    for index, entry in enumerate(reversed(history), start=1):

        timestamp = entry.get(
            "timestamp",
            "Unknown time",
        )

        text = entry.get(
            "text",
            "",
        )

        result = entry.get(
            "result",
            {},
        )

        risk_level = result.get(
            "risk_level",
            "UNKNOWN",
        )

        risk_score = result.get(
            "risk_score",
            0,
        )

        icon = get_risk_icon(risk_level)

        history_text += (
            f"### {index}. {icon} {risk_level} — {risk_score}/100\n\n"
            f"**Time:** `{timestamp}`\n\n"
            f"**Message:**\n> {text}\n\n"
            "---\n\n"
        )

    return history_text


def format_history_count():
    count = len(load_history())

    return (
        f"📊 **Total Analyses:** `{count}`"
    )


# =============================================================
# Dashboard
# =============================================================

def build_dashboard():

    history = load_history()

    if not history:
        return (
            "## 📊 Security Dashboard\n\n"
            "### 📭 No data available yet\n\n"
            "Run some security analyses to populate the dashboard."
        )

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "SAFE": 0,
        "OTHER": 0,
    }

    scores = []

    for entry in history:

        result = entry.get(
            "result",
            {},
        )

        risk_level = str(
            result.get(
                "risk_level",
                "OTHER",
            )
        ).upper()

        risk_score = result.get(
            "risk_score",
            0,
        )

        if risk_level in counts:
            counts[risk_level] += 1
        else:
            counts["OTHER"] += 1

        try:
            scores.append(
                float(risk_score)
            )

        except (TypeError, ValueError):
            pass

    total = len(history)

    average_score = (
        sum(scores) / len(scores)
        if scores
        else 0
    )

    most_common = max(
        counts,
        key=counts.get,
    )

    def percentage(value):

        if total:
            return (
                value / total
            ) * 100

        return 0

    dashboard = (
        "## 📊 Security Dashboard\n\n"

        "### Overview\n\n"

        "| Metric | Value |\n"
        "|---|---:|\n"

        f"| 📋 Total Analyses | **{total}** |\n"
        f"| 📈 Average Risk Score | **{average_score:.1f}/100** |\n"
        f"| ⚠️ Most Common Risk | **{most_common}** |\n\n"

        "---\n\n"

        "### 🛡️ Risk Distribution\n\n"

        f"- 🔴 **CRITICAL:** {counts['CRITICAL']} "
        f"({percentage(counts['CRITICAL']):.1f}%)\n"

        f"- 🟠 **HIGH:** {counts['HIGH']} "
        f"({percentage(counts['HIGH']):.1f}%)\n"

        f"- 🟡 **MEDIUM:** {counts['MEDIUM']} "
        f"({percentage(counts['MEDIUM']):.1f}%)\n"

        f"- 🔵 **LOW:** {counts['LOW']} "
        f"({percentage(counts['LOW']):.1f}%)\n"

        f"- 🟢 **SAFE:** {counts['SAFE']} "
        f"({percentage(counts['SAFE']):.1f}%)\n\n"

        "---\n\n"

        "### 📌 Security Snapshot\n\n"

        f"- 🔴 Critical threats: **{counts['CRITICAL']}**\n"
        f"- 🟠 High-risk analyses: **{counts['HIGH']}**\n"
        f"- 🟡 Medium-risk analyses: **{counts['MEDIUM']}**\n"
        f"- 🔵 Low-risk analyses: **{counts['LOW']}**\n"
        f"- 🟢 Safe analyses: **{counts['SAFE']}**"
    )

    if counts["OTHER"] > 0:

        dashboard += (
            f"\n- ⚪ Other/unknown: "
            f"**{counts['OTHER']}**"
        )

    return dashboard


# =============================================================
# UI Actions
# =============================================================

def refresh_history():

    return (
        format_history(),
        format_history_count(),
        build_dashboard(),
    )


def clear_history_action():

    clear_history()

    return (
        "### 🗑️ History cleared successfully.",
        "📊 **Total Analyses:** `0`",
        build_dashboard(),
    )


def refresh_dashboard():

    return build_dashboard()


# =============================================================
# Main Analysis
# =============================================================

def analyze_text(text):

    if not text or not text.strip():

        return (
            "⚠️ **No text provided**\n\n"
            "Enter a message above and click **Analyze Security Risk**.",

            "### 📭 No security findings\n\n"
            "There is no message to analyze.",

            "### 🤖 AI Classification\n\n"
            "No classification available.",

            "### 📊 Score Breakdown\n\n"
            "No score available.",

            "No security report generated.",

            format_history(),

            format_history_count(),

            build_dashboard(),
        )

    result = pipeline.analyze(text)

    risk_level = result["risk_level"]

    risk_score = result["risk_score"]

    classifier = result["classifier"]

    label = classifier["label"]

    confidence = classifier["confidence"]

    findings = result["findings"]

    risk_icon = get_risk_icon(
        risk_level
    )

    risk_description = get_risk_description(
        risk_level
    )

    # ---------------------------------------------------------
    # Risk Summary
    # ---------------------------------------------------------

    summary = (
        f"## {risk_icon} {risk_level} RISK\n\n"
        f"# {risk_score}/100\n\n"
        f"**Overall security risk score**\n\n"
        f"_{risk_description}_"
    )

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    if findings:

        findings_text = (
            f"**{len(findings)} security indicator(s) detected.**\n\n"
        )

        for index, finding in enumerate(
            findings,
            start=1,
        ):

            finding_icon = get_risk_icon(
                finding["severity"]
            )

            findings_text += (
                f"### {finding_icon} {index}. "
                f"{finding['keyword']}\n\n"

                f"**Severity:** "
                f"`{finding['severity']}`  \n"

                f"**Type:** "
                f"`{finding['type']}`  \n"
            )

            if "category" in finding:

                findings_text += (
                    f"**Category:** "
                    f"`{finding['category']}`  \n"
                )

            if "score_contribution" in finding:

                findings_text += (
                    f"**Score Contribution:** "
                    f"`+{finding['score_contribution']}`\n\n"
                )

            findings_text += (
                "---\n\n"
            )

    else:

        findings_text = (
            "### 🟢 No rule-based security findings detected\n\n"
            "The analyzer did not detect any known suspicious "
            "security patterns or keywords."
        )

    # ---------------------------------------------------------
    # AI Classification
    # ---------------------------------------------------------

    ai_result = (
        f"## 🤖 {label}\n\n"

        f"**Confidence:** "
        f"`{confidence:.2f}`\n\n"

        f"The security classifier identified this message "
        f"as **{label}**."
    )

    # ---------------------------------------------------------
    # Score Breakdown
    # ---------------------------------------------------------

    pattern_score = result["pattern_score"]

    classifier_score = result["classifier_score"]

    score_breakdown = (
        "### Rule-Based Analysis\n\n"
        f"`{pattern_score}/100`\n\n"

        "### AI Classifier\n\n"
        f"`{classifier_score}/100`\n\n"

        "### Final Risk Score\n\n"
        f"# {risk_score}/100"
    )

    # ---------------------------------------------------------
    # Security Report
    # ---------------------------------------------------------

    security_report = generate_report(
        findings,
        risk_score,
        risk_level,
    )

    return (
        summary,
        findings_text,
        ai_result,
        score_breakdown,
        security_report,
        format_history(),
        format_history_count(),
        build_dashboard(),
    )


# =============================================================
# Custom CSS
# =============================================================

custom_css = """
/* =========================================================
   Global Layout
   ========================================================= */

body {
    background: #0b1020;
}

.gradio-container {
    max-width: 1150px !important;
    margin: auto !important;
    padding-bottom: 40px !important;
}

/* =========================================================
   Header
   ========================================================= */

#title {
    text-align: center;
    margin-top: 10px;
    margin-bottom: 4px;
}

#subtitle {
    text-align: center;
    opacity: 0.78;
    margin-bottom: 18px;
}

/* =========================================================
   Section Headings
   ========================================================= */

.section-heading {
    margin-top: 28px;
    margin-bottom: 12px;
}

/* =========================================================
   Analysis Input
   ========================================================= */

.input-card {
    border-radius: 14px;
    padding: 4px;
}

/* =========================================================
   Analyze Button
   ========================================================= */

#analyze-button {
    min-height: 58px;
    font-size: 18px;
    font-weight: 700;
    border-radius: 12px;
    margin-top: 8px;
}

/* =========================================================
   Output Cards
   ========================================================= */

.output-card {
    border-radius: 14px !important;
    padding: 14px !important;
}

.summary-card {
    min-height: 210px;
}

.ai-card {
    min-height: 210px;
}

.findings-card {
    border-radius: 14px !important;
    padding: 16px !important;
}

.score-card {
    border-radius: 14px !important;
    padding: 16px !important;
}

/* =========================================================
   Report
   ========================================================= */

.report-card {
    border-radius: 14px !important;
    overflow: hidden;
}

.report-card textarea {
    font-family: Consolas, "Courier New", monospace !important;
}

/* =========================================================
   Dashboard
   ========================================================= */

.dashboard-card {
    border-radius: 14px !important;
    padding: 18px !important;
}

/* =========================================================
   History
   ========================================================= */

.history-card {
    border-radius: 14px !important;
    padding: 16px !important;
}

/* =========================================================
   Buttons
   ========================================================= */

.secondary-button {
    border-radius: 10px !important;
}

/* =========================================================
   Footer
   ========================================================= */

.footer {
    text-align: center;
    opacity: 0.55;
    margin-top: 35px;
    padding-top: 10px;
}

.footer hr {
    opacity: 0.25;
}
"""


# =============================================================
# Gradio Application
# =============================================================

with gr.Blocks(
    title="RazorGuard-AI"
) as demo:

    # ---------------------------------------------------------
    # Header
    # ---------------------------------------------------------

    gr.Markdown(
        "# 🛡️ RazorGuard-AI",
        elem_id="title",
    )

    gr.Markdown(
        "### AI-Powered Security Message Analyzer",
        elem_id="subtitle",
    )

    gr.Markdown(
        "Analyze messages for **credential harvesting, phishing, "
        "security bypass attempts, malware-related instructions, "
        "and other suspicious security patterns.**\n\n"

        "> **RazorGuard-AI combines rule-based detection with an "
        "AI security classifier to produce a unified risk assessment.**"
    )

    # ---------------------------------------------------------
    # Input
    # ---------------------------------------------------------

    gr.Markdown(
        "## 🔍 Analyze a Message",
        elem_classes="section-heading",
    )

    with gr.Group(
        elem_classes="input-card"
    ):

        text_input = gr.Textbox(
            label="Message to Analyze",
            placeholder=(
                "Example: Send me your password and "
                "disable antivirus immediately."
            ),
            lines=6,
        )

        analyze_button = gr.Button(
            "🔍 Analyze Security Risk",
            variant="primary",
            elem_id="analyze-button",
        )

    # ---------------------------------------------------------
    # Risk Assessment
    # ---------------------------------------------------------

    gr.Markdown(
        "## 🛡️ Risk Assessment",
        elem_classes="section-heading",
    )

    with gr.Row():

        with gr.Column():

            summary_output = gr.Markdown(
                elem_classes=[
                    "output-card",
                    "summary-card",
                ],
            )

        with gr.Column():

            ai_output = gr.Markdown(
                elem_classes=[
                    "output-card",
                    "ai-card",
                ],
            )

    # ---------------------------------------------------------
    # Findings
    # ---------------------------------------------------------

    gr.Markdown(
        "## 🚨 Security Findings",
        elem_classes="section-heading",
    )

    findings_output = gr.Markdown(
        elem_classes=[
            "output-card",
            "findings-card",
        ],
    )

    # ---------------------------------------------------------
    # Score Breakdown
    # ---------------------------------------------------------

    gr.Markdown(
        "## 📊 Score Breakdown",
        elem_classes="section-heading",
    )

    score_output = gr.Markdown(
        elem_classes=[
            "output-card",
            "score-card",
        ],
    )

    # ---------------------------------------------------------
    # Security Report
    # ---------------------------------------------------------

    gr.Markdown(
        "## 📋 Security Report",
        elem_classes="section-heading",
    )

    report_output = gr.Code(
        value="Generated Security Report",
        language="markdown",
        interactive=False,
        label="Security Report",
        elem_classes="report-card",
    )

    # ---------------------------------------------------------
    # Dashboard
    # ---------------------------------------------------------

    gr.Markdown(
        "## 📈 Security Dashboard",
        elem_classes="section-heading",
    )

    dashboard_output = gr.Markdown(
        value=build_dashboard(),
        elem_classes=[
            "output-card",
            "dashboard-card",
        ],
    )

    dashboard_refresh_button = gr.Button(
        "🔄 Refresh Dashboard",
        variant="secondary",
        elem_classes="secondary-button",
    )

    # ---------------------------------------------------------
    # History
    # ---------------------------------------------------------

    gr.Markdown(
        "## 📜 Analysis History",
        elem_classes="section-heading",
    )

    history_count = gr.Markdown(
        value=format_history_count(),
    )

    with gr.Row():

        refresh_button = gr.Button(
            "🔄 Refresh History",
            variant="secondary",
            elem_classes="secondary-button",
        )

        clear_button = gr.Button(
            "🗑️ Clear History",
            variant="stop",
            elem_classes="secondary-button",
        )

    history_output = gr.Markdown(
        value=format_history(),
        elem_classes=[
            "output-card",
            "history-card",
        ],
    )

    # ---------------------------------------------------------
    # Event Connections
    # ---------------------------------------------------------

    analyze_button.click(
        fn=analyze_text,
        inputs=text_input,
        outputs=[
            summary_output,
            findings_output,
            ai_output,
            score_output,
            report_output,
            history_output,
            history_count,
            dashboard_output,
        ],
    )

    refresh_button.click(
        fn=refresh_history,
        inputs=[],
        outputs=[
            history_output,
            history_count,
            dashboard_output,
        ],
    )

    clear_button.click(
        fn=clear_history_action,
        inputs=[],
        outputs=[
            history_output,
            history_count,
            dashboard_output,
        ],
    )

    dashboard_refresh_button.click(
        fn=refresh_dashboard,
        inputs=[],
        outputs=dashboard_output,
    )

    # ---------------------------------------------------------
    # Footer
    # ---------------------------------------------------------

    gr.Markdown(
        '<div class="footer">'
        '<hr>'
        '<b>RazorGuard-AI</b> | Security Analysis Prototype'
        '<br>'
        'Built with Python • Gradio • Transformers'
        '</div>'
    )


    # ---------------------------------------------------------
    # Page Load Refresh
    # ---------------------------------------------------------
    demo.load(
        fn=refresh_history,
        inputs=[],
        outputs=[
            history_output,
            history_count,
            dashboard_output,
        ],
    )
    
# =============================================================
# Launch
# =============================================================

if __name__ == "__main__":

    demo.launch(
        theme=gr.themes.Soft(),
        css=custom_css,
    )