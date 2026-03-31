from fastapi import FastAPI
from app.evaluator import run_evaluation

app = FastAPI(title="LLM Eval & Red-Team Framework")

@app.get("/")
def root():
    return {"status": "running", "message": "LLM Evaluation Framework"}

@app.post("/evaluate")
def evaluate(prompt: str, expected: str):
    result = run_evaluation(prompt, expected)
    return result