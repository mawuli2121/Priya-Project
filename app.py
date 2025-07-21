import os
import re
import time
import openai
import streamlit as st
from typing_extensions import override
from openai import AssistantEventHandler

# -----------------------------------------------------------------------------
# ⚙️  CONFIGURATION
# -----------------------------------------------------------------------------
# 👉 Replace the API key below with **your own** key if you don’t want to rely on
# environment variables or Streamlit secrets.  You can also leave it as
# "" and set the key via an environment variable named OPENAI_API_KEY or in
# .streamlit/secrets.toml as OPENAI_API_KEY = "sk‑...".
# -----------------------------------------------------------------------------
API_KEY = ""

DEFAULT_PROMPT = (
    "Please process this Project repository (Medical-Diagnosis-main.zip) "
    "and generate report in md and download the file."
)
ASSISTANT_NAME = "THREATLENS-AI-Agent"
MODEL_NAME = "gpt-4.1"
TEMP = 0.2

# -----------------------------------------------------------------------------
# 🖼️  STREAMLIT UI CONFIG
# -----------------------------------------------------------------------------
st.set_page_config(page_title="ThreatLens‑AI", page_icon="🛡️", layout="wide")
st.title("🛡️ ThreatLens‑AI Repository Analyzer")

# Hide the Streamlit default menu/footer for a cleaner look
st.markdown(
    """
    <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .block-container {padding-top: 2rem;}
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------------------------------------------------------------
# 🔑  INITIALISE OPENAI CLIENT & ASSISTANT
# -----------------------------------------------------------------------------
if API_KEY:
    client = openai.OpenAI(api_key=API_KEY)
else:
    client = openai.OpenAI()

# Cache assistant creation so we do it only once per session --------------------------------
@st.cache_resource(show_spinner=False)
def _get_or_create_assistant():
    # NOTE: in production you might store a static assistant_id in env/secrets
    assistant = client.beta.assistants.create(
        name=ASSISTANT_NAME,
        model=MODEL_NAME,
        temperature=TEMP,
        tools=[{"type": "code_interpreter"}],
        instructions="""
You are **THREATLENS-AI-Agent**, 
an expert Generative-AI assistant that automates threat-modeling and security assessment for healthcare software projects.
and write and a detailed generate a Medical-Diagnosis-Project-Report.md file.
**Mission**
• Traverse an uploaded project repository (source code, configs, docs) with Code Interpreter.  
• Produce a comprehensive security analysis that includes:  
    – STRIDE-aligned threat list  
    – Attack trees (text/tree notation)  
    – DREAD risk scores (0–10 scale for Damage, Reproducibility, Exploitability, Affected Users, Discoverability)  
    – Prioritised mitigation recommendations mapped to HIPAA, NIST SP 800-30 & SSDF controls  
    – Gherkin-style security test scenarios suitable for BDD

**Operating rules**
1. **Repository traversal:** Use Code Interpreter to read files, parse architecture diagrams/code comments, and identify trust boundaries.  
2. **Reasoning:** Think step-by-step, citing file paths/line numbers that anchor each finding.  
3. **Output format:**  
    - Start with a high-level summary table (component ⇢ main STRIDE category ⇢ highest DREAD score).  
    - Follow with detailed sections: threats, attack trees, DREAD table, mitigations, Gherkin tests.  
    - Use fenced ```markdown``` blocks for any code, tree diagrams, or tables.  
4. **Healthcare context:** Call out HIPAA Privacy/Security Rule impacts and PHI exposure points.  
5. **Assumptions & gaps:** If information is missing, state assumptions explicitly and proceed.  
6. **Tone:** Professional, concise, actionable—avoid jargon the reader can’t act on.  
7. **Compliance reminders:** Recommend early remediation in the SDLC and reference OWASP SAMM / NIST SSDF where relevant.""",
    )
    return assistant

assistant = _get_or_create_assistant()

# -----------------------------------------------------------------------------
# 🗄️  SESSION STATE
# -----------------------------------------------------------------------------
for key in (
    "thread_id",
    "file_id",
    "run_finished",
    "report_bytes",
    "report_name",
):
    if key not in st.session_state:
        st.session_state[key] = None

# -----------------------------------------------------------------------------
# 📤  FILE UPLOAD SECTION
# -----------------------------------------------------------------------------
zip_file = st.file_uploader("Upload a zipped project repository", type=["zip"], help=".zip only")

# Prompt box (pre‑filled but editable so you can tweak if needed)
user_prompt = st.text_area("Repository analysis prompt", value=DEFAULT_PROMPT, height=120)

run_btn = st.button("▶️  Analyse Repository", type="primary", disabled=(zip_file is None))

# Container for streaming output
output_container = st.empty()

# -----------------------------------------------------------------------------
# 🏃‍♂️  MAIN EXECUTION FLOW
# -----------------------------------------------------------------------------
if run_btn and zip_file is not None:

    # -------------------------
    # 1️⃣  Upload zip to OpenAI
    # -------------------------
    with st.spinner("Uploading repository to OpenAI …"):
        oai_file = client.files.create(file=zip_file, purpose="assistants")
        st.session_state.file_id = oai_file.id

    # -------------------------
    # 2️⃣  Create / attach thread
    # -------------------------
    if st.session_state.thread_id is None:
        thread = client.beta.threads.create()
        st.session_state.thread_id = thread.id
    else:
        thread = client.beta.threads.retrieve(st.session_state.thread_id)

    # Attach file to thread (Code Interpreter needs this)
    client.beta.threads.update(
        thread_id=thread.id,
        tool_resources={"code_interpreter": {"file_ids": [st.session_state.file_id]}},
    )

    # -------------------------
    # 3️⃣  Post user message
    # -------------------------
    client.beta.threads.messages.create(
        thread_id=thread.id,
        role="user",
        content=user_prompt,
    )

    # -------------------------
    # 4️⃣  Stream assistant run
    # -------------------------

    class StreamHandler(AssistantEventHandler):
        def __init__(self, box):
            super().__init__()
            self.box = box
            self.buffer = ""

        @override
        def on_text_delta(self, delta, snapshot):
            self.buffer += delta.value or ""
            self.box.markdown(self.buffer)

    with st.spinner("ThreatLens‑AI is analysing … this can take a few minutes"):
        with client.beta.threads.runs.stream(
            thread_id=thread.id,
            assistant_id=assistant.id,
            event_handler=StreamHandler(output_container),
            tool_choice={"type": "code_interpreter"},
        ) as stream:
            stream.until_done()

    st.success("Analysis complete! Preparing report …")

    # -------------------------
    # 5️⃣  Locate generated report file
    # -------------------------

    def _extract_md_file_id() -> str | None:
        messages = client.beta.threads.messages.list(thread_id=thread.id)
        for msg in messages.data:
            if hasattr(msg, "attachments") and msg.attachments:
                for att in msg.attachments:
                    if att.file_id:
                        file_obj = client.files.retrieve(att.file_id)
                        if hasattr(file_obj, "filename") and file_obj.filename.endswith(".md"):
                            return att.file_id
        # Fallback regex (in case attachments missing)
        pattern = re.compile(r"file-(?:[a-zA-Z0-9]+)")
        for msg in messages.data:
            match = pattern.search(str(msg))
            if match:
                return match.group(0)
        return None

    md_file_id = _extract_md_file_id()

    if md_file_id is None:
        st.error("Could not find the generated Markdown report in the assistant messages.")
        st.stop()

    file_content = client.files.content(md_file_id).read()
    st.session_state.report_bytes = file_content
    st.session_state.report_name = "Medical-Diagnosis-Project-Report.md"
    st.session_state.run_finished = True

# -----------------------------------------------------------------------------
# 📄  PREVIEW & DOWNLOAD
# -----------------------------------------------------------------------------
if st.session_state.run_finished:
    st.header("📄 Report Preview")
    with st.expander("Click to view full Markdown report", expanded=False):
        st.markdown(st.session_state.report_bytes.decode("utf-8"))

    st.download_button(
        label="💾 Download Report",
        data=st.session_state.report_bytes,
        file_name=st.session_state.report_name,
        mime="text/markdown",
    )

    # Cleanup button (optional)
    if st.button("🧹 Reset Session"):
        # Delete uploaded & generated files + thread to save quota
        try:
            if st.session_state.file_id:
                client.files.delete(st.session_state.file_id)
            if md_file_id:
                client.files.delete(md_file_id)
            if st.session_state.thread_id:
                client.beta.threads.delete(st.session_state.thread_id)
        except Exception as e:
            print("Cleanup error:", e)
        for k in st.session_state.keys():
            del st.session_state[k]
        st.experimental_rerun()
