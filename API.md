# ShadowAPI API Reference

## Python Library Usage

```python
from shadowapi.core.har_parser import HARParser
from shadowapi.core.spec_builder import SpecBuilder
from shadowapi.engine.drift_detector import DriftDetector
from shadowapi.engine.reporter import ReportGenerator

# 1. Parse traffic archive
transactions = HARParser.parse_file("examples/traffic.har")

# 2. Synthesize runtime specification
builder = SpecBuilder(title="Runtime Observed API", version="1.0.0")
signatures = builder.build_signatures(transactions)
runtime_spec = builder.synthesize_openapi(signatures)

# 3. Analyze drift against ground truth
detector = DriftDetector.from_file("examples/declared_spec.json")
report = detector.analyze(signatures, transactions)

# 4. Generate report
ReportGenerator.print_terminal_summary(report)
html = ReportGenerator.generate_html_report(report)
```
