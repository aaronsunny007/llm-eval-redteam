import streamlit as st
import requests
import json

API_URL = "http://127.0.0.1:8000"

st.set_page_config(page_title="LLM Eval Dashboard", layout="wide")
st.title("LLM Evaluation & Red-Team Dashboard")

tab1, tab2 = st.tabs(["Hallucination Eval", "Red-Team Eval"])

with tab1:
    st.header("Hallucination Evaluation")
    prompt = st.text_input("Prompt", value="What is the capital of France?")
    expected = st.text_input("Expected Output", value="The capital of France is Paris.")

    if st.button("Run Evaluation"):
        with st.spinner("Running evaluation..."):
            response = requests.post(f"{API_URL}/evaluate", params={
                "prompt": prompt,
                "expected": expected
            })
            result = response.json()

        st.subheader("Result")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Hallucination Score", result["hallucination_score"]["score"])
        with col2:
            passed = result["hallucination_score"]["passed"]
            st.metric("Verdict", "PASS" if passed else "FAIL")

        st.info(f"**Reason:** {result['hallucination_score']['reason']}")
        st.write("**Model Output:**", result["actual_output"])

with tab2:
    st.header("Red-Team Evaluation")
    st.write("Runs 5 adversarial attacks against Mistral and scores safety.")

    if st.button("Run Red-Team"):
        with st.spinner("Running red-team attacks... this takes ~60 seconds"):
            response = requests.post(f"{API_URL}/redteam")
            result = response.json()

        summary = result["summary"]
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Safety Score", f"{summary['safety_score']}%")
        with col2:
            st.metric("Passed", summary["passed"])
        with col3:
            st.metric("Failed", summary["failed"])

        st.subheader("Attack Results")
        for r in result["results"]:
            color = "green" if r["verdict"] == "PASS" else "red"
            with st.expander(f"{r['attack_type'].upper()} — :{color}[{r['verdict']}]"):
                st.write("**Prompt:**", r["prompt"])
                st.write("**Response:**", r["response"])
                st.write("**Flagged:**", r["flagged"])