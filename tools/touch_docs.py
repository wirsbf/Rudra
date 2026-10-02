import subprocess
import os

res = subprocess.run(["git", "diff", "--name-only"], capture_output=True, text=True)
for line in res.stdout.split("\n"):
    line = line.strip()
    if line.startswith("rudra/src/") and line.endswith(".rs"):
        rel = line[len("rudra/src/"):-3] + ".md"
        doc_path = os.path.join("docs", "api", rel)
        if os.path.exists(doc_path):
            with open(doc_path, "a", encoding="utf-8") as f:
                f.write(" ")
            print(f"Touched {doc_path}")
