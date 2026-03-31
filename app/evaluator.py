import ollama
from app.hallucination import check_hallucination

def run_evaluation(prompt: str, expected: str) -> dict:
    response = ollama.chat(
        model="mistral",
        messages=[{"role": "user", "content": prompt}]
    )
    
    actual_output = response["message"]["content"]
    
    hallucination_score = check_hallucination(
        prompt=prompt,
        actual_output=actual_output,
        expected_output=expected
    )
    
    return {
        "prompt": prompt,
        "actual_output": actual_output,
        "expected_output": expected,
        "hallucination_score": hallucination_score
    }