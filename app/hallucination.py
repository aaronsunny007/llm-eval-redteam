from deepeval.metrics import HallucinationMetric
from deepeval.test_case import LLMTestCase
from deepeval.models import OllamaModel

def check_hallucination(prompt: str, actual_output: str, expected_output: str) -> dict:
    
    ollama_model = OllamaModel(model="mistral")
    
    test_case = LLMTestCase(
        input=prompt,
        actual_output=actual_output,
        context=[expected_output]
    )
    
    metric = HallucinationMetric(threshold=0.5, model=ollama_model)
    metric.measure(test_case)
    
    return {
        "score": metric.score,
        "passed": metric.is_successful(),
        "reason": metric.reason
    }