from src.core.execution_engine import ExecutionEngine

engine = ExecutionEngine("http://127.0.0.1:8000/chat")

results = engine.run_all()

for r in results:
    print(r)
