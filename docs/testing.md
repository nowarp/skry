# Testing Commands

## Run e2e tests for a specific rule
```bash
PYTHONPATH=src python3 -m pytest 'test/test_e2e_fixtures.py::TestE2EFixtures::test_fixture_expectations[RULE_NAME]' -v
```

## List expected/error markers
```bash
grep -rn "@expect: RULE_NAME" test/fixtures/e2e/RULE_NAME/
grep -rn "@false-positive RULE_NAME" test/fixtures/e2e/RULE_NAME/
grep -rn "@false-negative RULE_NAME" test/fixtures/e2e/RULE_NAME/
```

## Compare detected vs expected violations
```bash
PYTHONPATH=src python3 << 'EOF'
import sys, tempfile
from pathlib import Path
sys.path.insert(0, 'test')
from test_e2e_fixtures import parse_markers, load_llm_cache, load_all_rules
from core.context import ProjectContext
from analysis import run_structural_analysis, run_fact_propagation
from taint.guards import generate_guarded_sink_facts
from pipeline import run_filter_pass, run_llm_facts_pass

RULE = 'admin-drain-risk'  # change this
rule_dir = Path(f'test/fixtures/e2e/{RULE}')
move_files = sorted(rule_dir.glob('*.move'))
ctx = ProjectContext([str(f) for f in move_files])
run_structural_analysis(ctx, dump_facts=False)
with tempfile.TemporaryDirectory() as tmp:
    load_llm_cache(rule_dir, Path(tmp), ctx)
run_fact_propagation(ctx)
generate_guarded_sink_facts(ctx)
rules = [r for r in load_all_rules() if r.name == RULE]
fr = run_filter_pass(ctx, rules)
violations = list(fr.violations) + (run_llm_facts_pass(ctx, fr) if fr.candidates else [])

detected = {b.get('f','').split('::')[-1] for _,b in violations}
expected = [(mf.name, m.func_name) for mf in move_files for m in parse_markers(str(mf))[0]]
print(f"Detected: {len(detected)}, Expected: {len(expected)}")
print("\nMISSING:")
for f,fn in expected:
    if fn not in detected: print(f"  {fn} @ {f}")
EOF
```

## Debug facts for a function
```bash
PYTHONPATH=src python3 << 'EOF'
from pathlib import Path
from core.context import ProjectContext
from analysis import run_structural_analysis

ctx = ProjectContext(['path/to/file.move'])
run_structural_analysis(ctx, dump_facts=False)
for fp, fc in ctx.source_files.items():
    for f in fc.facts:
        if 'FUNC_NAME' in str(f.args):
            print(f)
EOF
```

## Run all tests
```bash
python3 -m pytest -q
```

## Run with coverage
```bash
python3 -m pytest --cov=src --cov-report=term-missing
```

## Lint
```bash
./scripts/lint.sh
```
