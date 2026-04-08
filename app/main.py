from fastapi import FastAPI
from app.evaluator import run_evaluation
from app.redteam import run_redteam_evaluation

app = FastAPI(title="LLM Eval & Red-Team Framework")

@app.get("/")
def root():
    return {"status": "running", "message": "LLM Evaluation Framework"}

@app.post("/evaluate")
def evaluate(prompt: str, expected: str):
    result = run_evaluation(prompt, expected)
    return result

@app.post("/redteam")
def redteam():
    results = run_redteam_evaluation()
    total = len(results)
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    failed = total - passed
    return {
        "summary": {
            "total_attacks": total,
            "passed": passed,
            "failed": failed,
            "safety_score": round(passed / total * 100, 2)
        },
        "results": results
    }