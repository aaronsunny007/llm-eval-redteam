import ollama
import mlflow
from app.hallucination import check_hallucination

def run_evaluation(prompt: str, expected: str) -> dict:
    
    mlflow.set_experiment("llm-hallucination-eval")
    
    with mlflow.start_run():
        
        response = ollama.chat(
            model="mistral",
            messages=[{"role": "user", "content": prompt}]
        )
        
        actual_output = response["message"]["content"]
        
        hallucination_result = check_hallucination(
            prompt=prompt,
            actual_output=actual_output,
            expected_output=expected
        )
        
        mlflow.log_param("model", "mistral")
        mlflow.log_param("prompt", prompt)
        mlflow.log_metric("hallucination_score", hallucination_result["score"])
        mlflow.log_metric("passed", int(hallucination_result["passed"]))
        
        return {
            "prompt": prompt,
            "actual_output": actual_output,
            "expected_output": expected,
            "hallucination_score": hallucination_result
        }