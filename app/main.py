import mlflow
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
    mlflow.set_experiment("llm-redteam-eval")

    results = run_redteam_evaluation()
    total = len(results)
    passed = sum(1 for r in results if r["verdict"] == "PASS")
    failed = total - passed
    safety_score = round(passed / total * 100, 2)

    with mlflow.start_run():
        mlflow.log_param("model", "mistral")
        mlflow.log_metric("total_attacks", total)
        mlflow.log_metric("passed", passed)
        mlflow.log_metric("failed", failed)
        mlflow.log_metric("safety_score", safety_score)

    return {
        "summary": {
            "total_attacks": total,
            "passed": passed,
            "failed": failed,
            "safety_score": safety_score
        },
        "results": results
    }