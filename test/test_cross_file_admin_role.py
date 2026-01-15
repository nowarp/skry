"""Tests for cross-file IsPrivileged fact accessibility.

Ensures that checks-privileged? works when:
- IsPrivileged fact is defined in module A (where the role struct is)
- Function being checked is in module B (imports the role)

This is critical for version-check-missing rule to skip privileged-guarded functions.
"""

import textwrap
import tempfile
import os
import shutil

from core.context import ProjectContext
from analysis import StructuralBuilder
from analysis.access_control import generate_checks_role_facts
from core.facts import Fact
from rules.hy_loader import load_hy_rules
from rules.eval_context import EvalContext


def _create_temp_project(files: dict[str, str]) -> str:
    """Create a temporary directory with multiple Move files.

    Args:
        files: {filename: content} dict

    Returns:
        Path to temporary directory
    """
    tmpdir = tempfile.mkdtemp()
    for filename, content in files.items():
        filepath = os.path.join(tmpdir, filename)
        with open(filepath, "w") as f:
            f.write(textwrap.dedent(content))
    return tmpdir


class TestCrossFileIsPrivileged:
    """Test that IsPrivileged facts are accessible across files."""

    def test_checks_privileged_cross_file(self):
        """
        checks-privileged? should return True for a function in module B
        that takes OwnerCap from module A, where IsPrivileged is stored.

        Setup:
        - ownership.move: defines OwnerCap struct (IsCapability, IsPrivileged)
        - pool.move: defines set_pause(cap: &OwnerCap) - should be privileged-guarded

        Expected: checks-privileged? returns True for set_pause
        """
        tmpdir = _create_temp_project({
            "ownership.move": """
                module test::ownership {
                    use sui::object::UID;

                    public struct OwnerCap has key {
                        id: UID,
                    }

                    fun init(ctx: &mut TxContext) {
                        transfer::transfer(OwnerCap {
                            id: object::new(ctx),
                        }, tx_context::sender(ctx));
                    }
                }
            """,
            "pool.move": """
                module test::pool {
                    use test::ownership::OwnerCap;

                    const VERSION: u64 = 1;

                    fun assert_version() {
                        // version check
                    }

                    public entry fun do_something() {
                        assert_version();
                        // normal operation
                    }

                    public entry fun set_pause(_owner_cap: &OwnerCap, val: bool) {
                        // No version check - but privileged-guarded, so should be OK
                    }
                }
            """,
        })

        try:
            # Run structural analysis
            paths = [os.path.join(tmpdir, f) for f in ["ownership.move", "pool.move"]]
            ctx = ProjectContext(paths)
            StructuralBuilder().build(ctx)

            # Manually add IsPrivileged fact (normally done by LLM in pass 2)
            # This simulates the LLM confirming OwnerCap is a privileged role
            ownership_file = [p for p in paths if "ownership" in p][0]
            ctx.source_files[ownership_file].facts.append(
                Fact("IsPrivileged", ("test::ownership::OwnerCap",))
            )

            # Generate ChecksCapability facts
            generate_checks_role_facts(ctx)

            # Verify ChecksCapability was generated for set_pause
            pool_file = [p for p in paths if "pool" in p][0]
            pool_facts = ctx.source_files[pool_file].facts
            checks_role_facts = [f for f in pool_facts if f.name == "ChecksCapability"]

            # Should have ChecksCapability(test::ownership::OwnerCap, test::pool::set_pause)
            set_pause_roles = [f for f in checks_role_facts
                              if f.args[1] == "test::pool::set_pause"]
            assert len(set_pause_roles) == 1, f"Expected ChecksCapability for set_pause, got: {checks_role_facts}"
            assert set_pause_roles[0].args[0] == "test::ownership::OwnerCap"

            # Now test checks-privileged? via Hy
            # Create EvalContext for set_pause
            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=pool_file,
                current_source=ctx.source_files[pool_file].source_code,
                current_root=ctx.source_files[pool_file].root,
            )

            # Call checks-privileged? via the Hy module
            # Hy mangles function names: checks-privileged? -> hyx_checks_privilegedXquestion_markX
            import rules.hy.builtins as builtins_module

            # Get the function using Hy's name mangling
            checks_privileged = getattr(builtins_module, "hyx_checks_privilegedXquestion_markX", None)
            if checks_privileged is None:
                # Fallback: use dir to find the function
                funcs = [f for f in dir(builtins_module) if "privileged" in f.lower()]
                assert funcs, f"Could not find checks-privileged? in builtins. Available: {dir(builtins_module)}"
                checks_privileged = getattr(builtins_module, funcs[0])

            result = checks_privileged(
                "test::pool::set_pause",
                pool_facts,
                eval_ctx,
            )

            # THIS IS THE KEY ASSERTION - should be True now that we fixed the cross-file access
            assert result is True, (
                "checks-privileged? should return True for set_pause because it has OwnerCap param. "
                f"IsPrivileged facts: {[f for f in ctx.source_files[ownership_file].facts if f.name == 'IsPrivileged']}"
            )

        finally:
            shutil.rmtree(tmpdir)

    def test_version_check_missing_skips_privileged_functions(self):
        """
        version-check-missing rule should NOT fire for privileged-guarded functions.

        This is an end-to-end test using the real rule.
        """
        tmpdir = _create_temp_project({
            "ownership.move": """
                module test::ownership {
                    use sui::object::UID;

                    public struct OwnerCap has key {
                        id: UID,
                    }
                }
            """,
            "pool.move": """
                module test::pool {
                    use test::ownership::OwnerCap;

                    const VERSION: u64 = 1;

                    fun assert_version() {
                        // version check
                    }

                    public entry fun stake() {
                        assert_version();
                    }

                    public entry fun unstake() {
                        assert_version();
                    }

                    public entry fun set_pause(_owner_cap: &OwnerCap, val: bool) {
                        // No version check - emergency privileged function
                    }
                }
            """,
        })

        try:
            paths = [os.path.join(tmpdir, f) for f in ["ownership.move", "pool.move"]]
            ctx = ProjectContext(paths)
            StructuralBuilder().build(ctx)

            # Add IsPrivileged (simulating LLM)
            ownership_file = [p for p in paths if "ownership" in p][0]
            ctx.source_files[ownership_file].facts.append(
                Fact("IsPrivileged", ("test::ownership::OwnerCap",))
            )

            # Add project-level version feature
            ctx.project_facts.append(Fact("FeatureVersion", (True,)))

            # Add HasVersionCheck and IsVersionCheckMethod facts
            pool_file = [p for p in paths if "pool" in p][0]
            ctx.source_files[pool_file].facts.extend([
                Fact("HasVersionCheck", ("test::pool::stake",)),
                Fact("HasVersionCheck", ("test::pool::unstake",)),
                Fact("IsVersionCheckMethod", ("test::pool::assert_version",)),
            ])

            generate_checks_role_facts(ctx)

            # Load version-check-missing rule
            rules = load_hy_rules("rules/structural.hy")
            version_rule = next(r for r in rules if r.name == "version-check-missing")

            # Find bindings for pool.move
            from test_utils import find_hy_bindings
            pool_facts = ctx.source_files[pool_file].facts
            bindings = find_hy_bindings(version_rule, pool_facts)

            # Should have binding for set_pause (it's public entry)
            set_pause_binding = next(
                (b for b in bindings if b["f"] == "test::pool::set_pause"),
                None
            )
            assert set_pause_binding is not None, "set_pause should have a binding"

            # Evaluate predicate for set_pause
            eval_ctx = EvalContext(
                ctx=ctx,
                current_file=pool_file,
                current_source=ctx.source_files[pool_file].source_code,
                current_root=ctx.source_files[pool_file].root,
            )

            # The filter clause should return False (no violation) because:
            # 1. set_pause has OwnerCap param
            # 2. OwnerCap is IsPrivileged
            # 3. checks-privileged? should return True
            # 4. Rule has (not (checks-privileged? ...))
            result = version_rule.filter_clause(
                "test::pool::set_pause",
                pool_facts,
                eval_ctx,
            )

            # THIS SHOULD BE FALSE (no violation) but currently returns True
            # because IsPrivileged is not accessible
            assert result is False, (
                "version-check-missing should NOT fire for set_pause because it's privileged-guarded. "
                "The rule has (not (checks-privileged? ...)) but IsPrivileged fact is not accessible."
            )

        finally:
            shutil.rmtree(tmpdir)
