"""Benign fixture: repository read plus dedicated output write."""

import csv
import json
from pathlib import Path


values = []
with Path("data/sample.csv").open(encoding="utf-8") as source:
    for row in csv.DictReader(source):
        values.append(float(row["value"]))

Path("/output/result.json").write_text(
    json.dumps({"mean": sum(values) / len(values)}),
    encoding="utf-8",
)

