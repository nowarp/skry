"""E2E fixture verification using marker-based expectations.

Discovers all rule directories in test/fixtures/e2e/ and runs analysis
to verify that @expect markers match actual violations.

Usage:
    pytest test/test_e2e_fixtures.py -v
    pytest test/test_e2e_fixtures.py::TestE2EFixtures::test_fixture_expectations[duplicated-branch-condition] -v
"""

import json
from pathlib import Path
from typing import List, Dict

import pytest

from core.context import ProjectContext
from core.facts import Fact
from analysis import run_structural_analysis, run_fact_propagation
from rules.hy_loader import load_hy_rules
from pipeline import run_filter_pass, run_llm_facts_pass
from taint.guards import generate_guarded_sink_facts
from e2e_markers import parse_all_markers, InjectedFact


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "e2e"
RULES_DIR = Path(__file__).parent.parent / "rules"


def discover_rule_directories() -> List[str]:
    """Discover all rule directories in test/fixtures/e2e/."""
    rule_dirs = []
    for item in sorted(FIXTURES_DIR.iterdir()):
        if item.is_dir() and not item.name.startswith('_'):
            rule_dirs.append(item.name)
    return rule_dirs


def load_all_rules():
    """Load all rules from rules/*.hy files."""
    rules = []
    for rule_file in RULES_DIR.glob("*.hy"):
        rules.extend(load_hy_rules(str(rule_file)))
    return rules


def build_inject_facts(injected: List[InjectedFact]) -> Dict[str, List[Fact]]:
    """Build inject_facts dict from InjectedFact list.

    Format: {"project": [...], "file": [...]}

    Fact string format: "FactName(arg1, arg2, ...)"
    """
    project_facts = []
    file_facts = []

    for inj in injected:
        # Parse fact string: "FactName(arg1, arg2, ...)"
        fact_str = inj.fact_string.strip()
        if not fact_str:
            continue

        # Extract fact name and args
        if '(' not in fact_str:
            continue

        fact_name = fact_str[:fact_str.index('(')]
        args_str = fact_str[fact_str.index('(') + 1:fact_str.rindex(')')]

        # Parse args (simple comma split, handles quoted strings)
        args = []
        if args_str.strip():
            # Simple arg parsing (doesn't handle nested parens/quotes)
            for arg in args_str.split(','):
                arg = arg.strip()
                # Remove quotes if present
                if arg.startswith('"') and arg.endswith('"'):
                    arg = arg[1:-1]
                elif arg.startswith("'") and arg.endswith("'"):
                    arg = arg[1:-1]
                else:
                    # Try to convert to number or boolean if not quoted
                    if arg == 'True':
                        arg = True
                    elif arg == 'False':
                        arg = False
                    else:
                        try:
                            if '.' in arg:
                                arg = float(arg)
                            else:
                                arg = int(arg)
                        except ValueError:
                            pass  # Keep as string
                args.append(arg)

        fact = Fact(fact_name, tuple(args))

        # Project-level facts go to project scope
        if fact_name in ("ProjectCategory", "FeatureVersion", "FeaturePause"):
            project_facts.append(fact)
        else:
            file_facts.append(fact)

    result = {}
    if project_facts:
        result["project"] = project_facts
    if file_facts:
        result["file"] = file_facts

    return result


def load_llm_cache(rule_dir: Path, tmp_path: Path, ctx: "ProjectContext") -> bool:
    """Load llm_cache.json if exists and inject facts into context.

    Args:
        rule_dir: Path to rule fixture directory
        tmp_path: pytest tmp_path (unused but kept for compatibility)
        ctx: ProjectContext to inject facts into

    Returns:
        True if cache was loaded and facts injected, False otherwise
    """
    cache_file = rule_dir / "llm_cache.json"
    if not cache_file.exists():
        return False

    # Load cache data
    with open(cache_file) as f:
        cache_data = json.load(f)

    # Process UnifiedClassify (struct classification) facts
    if "UnifiedClassify" in cache_data:
        for struct_fqn, classification in cache_data["UnifiedClassify"].items():
            # Inject struct classification facts based on the cache

            # Find the file containing this struct
            target_file = None
            for file_path, file_ctx in ctx.source_files.items():
                if any(f.name == "Struct" and f.args[0] == struct_fqn for f in file_ctx.facts):
                    target_file = file_path
                    break

            if not target_file:
                continue

            file_ctx = ctx.source_files[target_file]

            # Inject IsCapability fact
            if classification.get("is_role", False):
                fact = Fact("IsCapability", (struct_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            # Inject IsPrivileged fact
            if classification.get("is_privileged", False):
                fact = Fact("IsPrivileged", (struct_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)
            else:
                # Inject NotPrivileged if not privileged
                fact = Fact("NotPrivileged", (struct_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            # Inject IsUserAsset fact
            is_user_asset = classification.get("is_user_asset", False)
            fact = Fact("IsUserAsset", (struct_fqn, is_user_asset))
            if fact not in ctx.semantic_facts:
                ctx.semantic_facts.append(fact)

            # Inject IsConfig fact
            if classification.get("is_config", False):
                fact = Fact("IsConfig", (struct_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            # Inject IsStateContainer fact
            if classification.get("is_state_container", False):
                fact = Fact("IsStateContainer", (struct_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            # Inject field classification facts (all field facts have confidence)
            for field_name in classification.get("config_fields", []):
                fact = Fact("FieldClassification", (struct_fqn, field_name, "config_value", False, 1.0, ""))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            for field_name in classification.get("mutable_config_fields", []):
                fact1 = Fact("FieldClassification", (struct_fqn, field_name, "mutable_config", False, 1.0, ""))
                fact2 = Fact("FieldClassification", (struct_fqn, field_name, "config_value", False, 1.0, ""))
                if fact1 not in file_ctx.facts:
                    file_ctx.facts.append(fact1)
                if fact2 not in file_ctx.facts:
                    file_ctx.facts.append(fact2)

            for field_name in classification.get("state_fields", []):
                fact = Fact("FieldClassification", (struct_fqn, field_name, "state", False, 1.0, ""))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            for field_name in classification.get("protocol_invariant_fields", []):
                fact = Fact("FieldClassification", (struct_fqn, field_name, "protocol_invariant", False, 1.0, ""))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            for field_name in classification.get("privileged_fields", []):
                fact = Fact("FieldClassification", (struct_fqn, field_name, "privileged_address", False, 1.0, ""))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

            for field_name in classification.get("lock_fields", []):
                fact = Fact("FieldClassification", (struct_fqn, field_name, "lock", False, 1.0, ""))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

    # Process AccessControlClassify (function classification) facts
    if "AccessControlClassify" in cache_data:
        for func_fqn, classification in cache_data["AccessControlClassify"].items():
            # Find the file containing this function
            target_file = None
            for file_path, file_ctx in ctx.source_files.items():
                if any(f.name == "Fun" and f.args[0] == func_fqn for f in file_ctx.facts):
                    target_file = file_path
                    break

            if not target_file:
                continue

            file_ctx = ctx.source_files[target_file]

            # Inject LLM access control facts
            if classification.get("is_vulnerable", False):
                fact = Fact("LLMVulnerableAccessControl", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)
                # Also inject drain-specific fact (for admin-drain-risk rule compatibility)
                drain_fact = Fact("LLMArbitraryDrain", (func_fqn,))
                if drain_fact not in file_ctx.facts:
                    file_ctx.facts.append(drain_fact)
                # Also inject sensitive setter fact (for unauth-sensitive-setter rule)
                setter_fact = Fact("LLMSensitiveSetter", (func_fqn,))
                if setter_fact not in file_ctx.facts:
                    file_ctx.facts.append(setter_fact)
            elif classification.get("has_access_control", False):
                fact = Fact("LLMHasAccessControl", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)
                # Also inject drain-specific fact (for admin-drain-risk rule compatibility)
                safe_drain_fact = Fact("LLMCallerOwnsValue", (func_fqn,))
                if safe_drain_fact not in file_ctx.facts:
                    file_ctx.facts.append(safe_drain_fact)
                # Also inject sensitive setter fact (for unauth-sensitive-setter rule)
                safe_setter_fact = Fact("LLMHasSetterAuth", (func_fqn,))
                if safe_setter_fact not in file_ctx.facts:
                    file_ctx.facts.append(safe_setter_fact)

    # Process TransferClassify (missing-transfer rule) facts
    if "TransferClassify" in cache_data:
        for func_fqn, classification in cache_data["TransferClassify"].items():
            # Find the file containing this function
            target_file = None
            for file_path, file_ctx in ctx.source_files.items():
                if any(f.name == "Fun" and f.args[0] == func_fqn for f in file_ctx.facts):
                    target_file = file_path
                    break

            if not target_file:
                continue

            file_ctx = ctx.source_files[target_file]

            # Schema: {value_reaches_recipient: bool, is_helper_function: bool}
            value_reaches = classification.get("value_reaches_recipient", True)
            is_helper = classification.get("is_helper_function", False)

            if not value_reaches and not is_helper:
                # Vulnerable: value never transferred
                fact = Fact("LLMMissingTransfer", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)
            else:
                # Safe: value reaches recipient or is helper
                fact = Fact("LLMValueReachesRecipient", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

    # Process version feature detection
    if "FeatureVersion" in cache_data:
        version_info = cache_data["FeatureVersion"]
        if version_info.get("has_versioning", False):
            # Inject FeatureVersion fact into project facts
            fact = Fact("FeatureVersion", (True,))
            if fact not in ctx.project_facts:
                ctx.project_facts.append(fact)

            # Inject version check functions
            for func in version_info.get("version_check_functions", []):
                fact = Fact("HasVersionCheck", (func,))
                if fact not in ctx.project_facts:
                    ctx.project_facts.append(fact)

            # Inject version check methods
            for method in version_info.get("version_check_methods", []):
                fact = Fact("IsVersionCheckMethod", (method,))
                if fact not in ctx.project_facts:
                    ctx.project_facts.append(fact)

            # Inject version struct
            version_struct = version_info.get("version_struct")
            if version_struct:
                fact = Fact("IsVersion", (version_struct,))
                if fact not in ctx.project_facts:
                    ctx.project_facts.append(fact)

    # Process pause feature detection
    if "pause" in cache_data:
        pause_info = cache_data["pause"]
        if pause_info.get("has_pause", False):
            # Inject FeaturePause fact into project facts
            fact = Fact("FeaturePause", (True,))
            if fact not in ctx.project_facts:
                ctx.project_facts.append(fact)

            # Inject IsGlobalPauseField fact
            pause_struct = pause_info.get("pause_struct")
            pause_field = pause_info.get("pause_field")
            if pause_struct and pause_field:
                fact = Fact("IsGlobalPauseField", (pause_struct, pause_field))
                if fact not in ctx.project_facts:
                    ctx.project_facts.append(fact)

            # Inject ChecksPause facts for check_functions
            for func_name in pause_info.get("check_functions", []):
                # Find the file containing this function
                target_file = None
                for file_path, file_ctx in ctx.source_files.items():
                    if any(f.name == "Fun" and f.args[0] == func_name for f in file_ctx.facts):
                        target_file = file_path
                        break
                if target_file:
                    fact = Fact("ChecksPause", (func_name,))
                    if fact not in ctx.source_files[target_file].facts:
                        ctx.source_files[target_file].facts.append(fact)

            # Inject IsPauseControl facts for control_functions
            for func_name in pause_info.get("control_functions", []):
                fact = Fact("IsPauseControl", (func_name,))
                if fact not in ctx.project_facts:
                    ctx.project_facts.append(fact)

    # Process SensitiveField facts for sensitive-event-leak rule
    if "SensitiveField" in cache_data:
        for field_key, is_sensitive in cache_data["SensitiveField"].items():
            # Field key format: "struct_fqn::field_name"
            parts = field_key.rsplit("::", 1)
            if len(parts) != 2:
                continue
            struct_fqn, field_name = parts
            # Convert to FieldClassification with category="sensitive"
            negative = not is_sensitive
            fact = Fact("FieldClassification", (struct_fqn, field_name, "sensitive", negative, 1.0, ""))
            if fact not in ctx.sensitivity_facts:
                ctx.sensitivity_facts.append(fact)

    # Process InternalHelperExposureClassify facts
    if "InternalHelperExposureClassify" in cache_data:
        for func_fqn, classification in cache_data["InternalHelperExposureClassify"].items():
            # Find the file containing this function
            target_file = None
            for file_path, file_ctx in ctx.source_files.items():
                if any(f.name == "Fun" and f.args[0] == func_fqn for f in file_ctx.facts):
                    target_file = file_path
                    break

            if not target_file:
                continue

            file_ctx = ctx.source_files[target_file]

            # Inject LLM internal helper exposure facts
            if classification.get("is_internal_helper", False):
                fact = Fact("LLMInternalHelperExposure", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)
            else:
                fact = Fact("LLMSafeInternalHelper", (func_fqn,))
                if fact not in file_ctx.facts:
                    file_ctx.facts.append(fact)

    return True


class TestE2EFixtures:
    """Automated E2E tests using marker-based expectations."""

    @pytest.mark.parametrize("rule_name", discover_rule_directories())
    def test_fixture_expectations(self, rule_name: str, tmp_path):
        """Test that fixtures match marker expectations."""
        rule_dir = FIXTURES_DIR / rule_name

        # Collect all .move files
        move_files = list(rule_dir.glob("*.move"))
        if not move_files:
            pytest.skip(f"No .move files in {rule_dir}")

        # Parse markers from all files
        all_expected = []
        all_inject = []
        all_false_negatives = []
        all_false_positives = []

        for move_file in move_files:
            markers = parse_all_markers(str(move_file))
            all_expected.extend(markers.expected)
            all_inject.extend(markers.injected)
            all_false_negatives.extend(markers.false_negatives)
            all_false_positives.extend(markers.false_positives)

        # If no markers, skip
        if not all_expected and not all_false_negatives and not all_false_positives:
            pytest.skip(f"No markers in {rule_dir}")

        # Build inject_facts
        inject_facts = build_inject_facts(all_inject) if all_inject else None

        # Run analysis
        source_files = [str(f) for f in move_files]
        ctx = ProjectContext(source_files)
        run_structural_analysis(ctx)

        # Load LLM cache and inject facts BEFORE fact propagation
        # (fact propagation regenerates ChecksCapability which needs IsCapability facts)
        cache_loaded = load_llm_cache(rule_dir, tmp_path, ctx)

        # Inject facts if provided
        if inject_facts:
            if "project" in inject_facts:
                ctx.project_facts.extend(inject_facts["project"])
            if "file" in inject_facts:
                for file_ctx in ctx.source_files.values():
                    file_ctx.facts.extend(inject_facts["file"])

        # Run fact propagation (regenerates ChecksCapability with IsCapability facts from cache)
        run_fact_propagation(ctx)

        # Re-run orphan detection if cache was loaded (needed for IsCapability/IsEvent facts + ChecksCapability)
        # Must run AFTER fact propagation since it needs ChecksCapability facts
        if cache_loaded:
            from analysis.orphans import detect_orphan_roles, detect_orphan_events
            detect_orphan_roles(ctx)
            detect_orphan_events(ctx)

        # Generate guarded sink facts
        generate_guarded_sink_facts(ctx)

        # Load rules
        all_rules = load_all_rules()
        rules = [r for r in all_rules if r.name == rule_name]

        if not rules:
            pytest.fail(f"Rule '{rule_name}' not found")

        # Run filter pass
        filter_result = run_filter_pass(ctx, rules)

        # Run classify pass if there are candidates
        classify_violations = []
        if filter_result.candidates:
            classify_violations = run_llm_facts_pass(ctx, filter_result)

        # Collect actual violations (filter + classify)
        # Map: (rule_name, simple_name, file_path) -> full_name
        actual_violations = {}
        all_violations = list(filter_result.violations) + classify_violations

        for rule, binding in all_violations:
            entity_name = binding.get(rule.match_binding, "unknown")

            # Handle tuple entity names (struct.field patterns like mutable-config-field)
            if isinstance(entity_name, tuple):
                if len(entity_name) == 2:
                    # 2-tuple: (struct_name, field_name) - mutable-config-field pattern
                    struct_name, field_name = entity_name
                    file_path = None
                    for fp, file_ctx in ctx.source_files.items():
                        if any(f.name == "Struct" and f.args[0] == struct_name for f in file_ctx.facts):
                            file_path = fp
                            break
                    simple_name = struct_name.split("::")[-1] if "::" in struct_name else struct_name
                elif len(entity_name) == 3:
                    # 3-tuple: (func_name, struct_type, field_path) - writes-protocol-invariant pattern
                    func_name, struct_name, field_name = entity_name
                    file_path = None
                    for fp, file_ctx in ctx.source_files.items():
                        if any(f.name == "Fun" and f.args[0] == func_name for f in file_ctx.facts):
                            file_path = fp
                            break
                    simple_name = func_name.split("::")[-1] if "::" in func_name else func_name
                else:
                    # Fallback for other tuple lengths
                    simple_name = str(entity_name[0]).split("::")[-1]
                    file_path = None
                actual_violations[(rule.name, simple_name, file_path)] = entity_name
                continue

            # Find file for this entity
            file_path = None
            for fp, file_ctx in ctx.source_files.items():
                if rule.match_pattern == "fun":
                    if any(f.name == "Fun" and f.args[0] == entity_name for f in file_ctx.facts):
                        file_path = fp
                        break
                elif rule.match_pattern in ["capability", "event"]:
                    if any(f.name == "Struct" and f.args[0] == entity_name for f in file_ctx.facts):
                        file_path = fp
                        break
                    if any(f.name == "IsEvent" and f.args[0] == entity_name for f in file_ctx.facts):
                        file_path = fp
                        break

            simple_name = entity_name.split("::")[-1] if "::" in entity_name else entity_name
            actual_violations[(rule.name, simple_name, file_path)] = entity_name

        # Build expected set
        expected_violations = {
            (exp.rule_name, exp.func_name, exp.file_path)
            for exp in all_expected
        }

        # Verify: every @expect marker has a corresponding violation
        for exp in all_expected:
            key = (exp.rule_name, exp.func_name, exp.file_path)
            assert key in actual_violations, \
                f"Missing violation: {exp.rule_name} at {exp.file_path}:{exp.line_number} (func: {exp.func_name})"

        # Build set for false positive tracking
        false_positive_keys = {
            (fp.rule_name, fp.func_name, fp.file_path)
            for fp in all_false_positives
        }

        # Verify: every violation has a corresponding @expect or @false-positive marker
        for key, full_name in actual_violations.items():
            rule_name, simple_name, file_path = key
            if key not in expected_violations and key not in false_positive_keys:
                pytest.fail(
                    f"Unmarked violation: {rule_name} in {file_path} (func: {simple_name}). "
                    f"Add '// @expect: {rule_name}' marker."
                )

        # Check for fixed false negatives (now detected - marker should be upgraded to @expect)
        fixed_fn = []
        for fn in all_false_negatives:
            key = (fn.rule_name, fn.func_name, fn.file_path)
            if key in actual_violations:
                fixed_fn.append(fn)

        if fixed_fn:
            fn_list = "\n".join(
                f"  - {fn.func_name} in {Path(fn.file_path).name}:{fn.line_number}"
                for fn in fixed_fn
            )
            pytest.fail(
                f"Fixed false negatives detected! Change @false-negative to @expect:\n{fn_list}"
            )

        # Check for fixed false positives (no longer detected - marker should be removed)
        fixed_fp = []
        for fp in all_false_positives:
            key = (fp.rule_name, fp.func_name, fp.file_path)
            if key not in actual_violations:
                fixed_fp.append(fp)

        if fixed_fp:
            fp_list = "\n".join(
                f"  - {fp.func_name} in {Path(fp.file_path).name}:{fp.line_number}"
                for fp in fixed_fp
            )
            pytest.fail(
                f"Fixed false positives detected! Remove @false-positive marker:\n{fp_list}"
            )
