"""Unit tests for hooks/yolt_review.py (issue #44).

Covers the load-bearing pure functions of the self-improvement reviewer:

- grouping (`group_key` / `is_compound` / `split_tokens`),
- redaction to a shareable shape (`redact_command`),
- the glob-collision safety gate (`annotate_glob_collisions`) that stops
  the reviewer from recommending a `settings.json` allow glob which would
  also match a known non-safe command,
- approval correlation between the decision log and the ran log
  (`build_ran_index` / `was_approved`),
- end-to-end aggregation (`build_groups`),
- status-preserving regeneration (`merge_state` / `load_state`).

Runs with stdlib unittest only - no tree-sitter dependency:

    python3 -m unittest discover -v tests
"""

import contextlib
import datetime
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_DIR = REPO_ROOT / "hooks"
RULES_DIR = REPO_ROOT / "rules"
sys.path.insert(0, str(HOOKS_DIR))

from yolt_review import (  # noqa: E402
    KIND_FASTPATH,
    KIND_UNKNOWN,
    KIND_UNSAFE,
    MAX_EXAMPLES,
    MAX_PER_BUCKET,
    STATE_NAME,
    STATE_VERSION,
    annotate_glob_collisions,
    build_groups,
    build_override_fragment,
    build_ran_index,
    cmd_write_override,
    compute_override,
    correlate_approvals,
    group_key,
    is_compound,
    load_known_clis,
    load_state,
    merge_command_fragment,
    merge_state,
    redact_command,
    save_state,
    split_tokens,
    suggestion_id,
)


def _ts(second):
    """A fixed tz-aware UTC timestamp varying only by second."""
    retval = datetime.datetime(
        2024, 1, 1, 12, 0, second, tzinfo=datetime.timezone.utc)
    return retval


def _ts_at(minute=0, second=0):
    """A fixed tz-aware UTC timestamp at an offset minute/second."""
    retval = datetime.datetime(
        2024, 1, 1, 12, minute, second, tzinfo=datetime.timezone.utc)
    return retval


def _rec(decision, command, ts=None, reason=None):
    """Build a decision-log record dict the way yolt_analyzer writes it."""
    retval = {"decision": decision, "command": command}
    if ts is not None:
        retval["ts"] = ts.isoformat()
    if reason is not None:
        retval["reason"] = reason
    return retval


class TestGrouping(unittest.TestCase):

    def test_simple_command_groups_to_argv0_plus_subcommands(self):
        self.assertEqual(group_key("kubectl delete pod x"),
                         "kubectl delete pod")

    def test_grouping_stops_at_first_flag(self):
        self.assertEqual(group_key("gh api -X POST /repos"), "gh api")

    def test_grouping_stops_at_slash_token(self):
        self.assertEqual(group_key("gh api /repos/x"), "gh api")

    def test_grouping_respects_max_depth(self):
        # argv0 + 2 subcommands = depth 3; the 4th token is dropped.
        self.assertEqual(group_key("a b c d"), "a b c")

    def test_leading_env_assignment_is_dropped(self):
        self.assertEqual(group_key("FOO=bar kubectl get pods"),
                         "kubectl get pods")

    def test_compound_command_has_no_group(self):
        self.assertIsNone(group_key("cat x | grep y"))
        self.assertIsNone(group_key("a && b"))
        self.assertIsNone(group_key("echo `whoami`"))

    def test_empty_command_has_no_group(self):
        self.assertIsNone(group_key(""))
        self.assertIsNone(group_key("   "))

    def test_is_compound_detects_metacharacters(self):
        for command in ("a | b", "a; b", "a & b", "a > f", "a < f",
                        "a `b`", "a $(b)", "a\nb"):
            self.assertTrue(is_compound(command), command)

    def test_is_compound_false_for_plain_command(self):
        self.assertFalse(is_compound("kubectl get pods -n default"))

    def test_split_tokens_falls_back_on_unbalanced_quote(self):
        # Unterminated quote: shlex raises, whitespace split is used.
        self.assertEqual(split_tokens('echo "open'), ["echo", '"open'])


class TestRedaction(unittest.TestCase):

    def test_values_become_placeholder_flag_names_kept(self):
        # Each positional value redacts to its own placeholder, so the
        # shape preserves argument count without leaking values.
        shape = redact_command("kubectl get pods -n prod my-pod")
        self.assertEqual(shape, "kubectl get pods -n <...> <...>")

    def test_equals_flag_value_is_stripped(self):
        shape = redact_command("aws s3 ls --profile secret")
        self.assertEqual(shape, "aws s3 ls --profile <...>")

    def test_equals_inline_flag_value_is_stripped(self):
        shape = redact_command("tool run --token=abc123")
        self.assertEqual(shape, "tool run --token=<...>")

    def test_compound_command_is_opaque(self):
        self.assertEqual(redact_command("cat x | grep secret"),
                         "(compound command)")


class TestSuggestionId(unittest.TestCase):

    def test_id_is_stable_and_twelve_hex(self):
        first = suggestion_id(KIND_FASTPATH, "gh api")
        second = suggestion_id(KIND_FASTPATH, "gh api")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)
        int(first, 16)  # raises if not hex

    def test_id_varies_by_kind_and_prefix(self):
        self.assertNotEqual(suggestion_id(KIND_FASTPATH, "gh api"),
                            suggestion_id(KIND_UNSAFE, "gh api"))
        self.assertNotEqual(suggestion_id(KIND_FASTPATH, "gh api"),
                            suggestion_id(KIND_FASTPATH, "gh pr"))


class TestGlobCollisionGate(unittest.TestCase):
    """The safety-critical gate: a `Bash(prefix*)` allow glob must be
    flagged when it would also match a known non-safe command."""

    def test_collision_is_recorded(self):
        suggestion = {"prefix": "gh api"}
        nonsafe = {"gh api -X POST /repos/x", "gh pr merge 5"}
        annotate_glob_collisions(suggestion, nonsafe)
        self.assertEqual(suggestion["glob_collisions"],
                         ["gh api -X POST /repos/x"])

    def test_partially_overlapping_namespace_does_not_collide(self):
        # `gh pr view*` must NOT be vetoed by `gh pr merge`.
        suggestion = {"prefix": "gh pr view"}
        annotate_glob_collisions(suggestion, {"gh pr merge 5"})
        self.assertEqual(suggestion["glob_collisions"], [])

    def test_no_collision_yields_empty_list(self):
        suggestion = {"prefix": "ls"}
        annotate_glob_collisions(suggestion, set())
        self.assertEqual(suggestion["glob_collisions"], [])

    def test_own_group_commands_do_not_self_collide(self):
        # A friction suggestion's own examples are in the nonsafe set; the
        # glob trivially matches them. They must not count as collisions.
        suggestion = {"prefix": "kubectl get pods"}
        annotate_glob_collisions(suggestion, {"kubectl get pods foo"},
                                 own_commands={"kubectl get pods foo"})
        self.assertEqual(suggestion["glob_collisions"], [])

    def test_distinct_command_still_collides_despite_own(self):
        # Excluding own commands must not hide a genuinely different
        # non-safe command the glob would sweep in.
        suggestion = {"prefix": "foo"}
        annotate_glob_collisions(suggestion, {"foo", "foo bar baz"},
                                 own_commands={"foo"})
        self.assertEqual(suggestion["glob_collisions"], ["foo bar baz"])

    def test_collisions_are_capped(self):
        suggestion = {"prefix": "gh api"}
        nonsafe = {"gh api -X POST /{}".format(i) for i in range(10)}
        annotate_glob_collisions(suggestion, nonsafe)
        self.assertEqual(len(suggestion["glob_collisions"]), MAX_EXAMPLES)


class TestApprovalCorrelation(unittest.TestCase):

    def test_build_ran_index_groups_and_sorts(self):
        records = [
            {"command": "git push", "ts": _ts(30).isoformat()},
            {"command": "git push", "ts": _ts(10).isoformat()},
            {"command": "git push", "ts": _ts(20).isoformat()},
        ]
        index = build_ran_index(records)
        self.assertEqual(index["git push"], [_ts(10), _ts(20), _ts(30)])

    def test_build_ran_index_skips_incomplete_records(self):
        records = [
            {"command": "git push"},          # no ts
            {"ts": _ts(10).isoformat()},      # no command
            {"command": "ok", "ts": _ts(5).isoformat()},
        ]
        index = build_ran_index(records)
        self.assertEqual(list(index.keys()), ["ok"])

    def test_one_ran_record_approves_only_one_prompt(self):
        # Regression (PR #47 review): two prompts for the same command, a
        # single later ran-record. Exactly one prompt is approved, not
        # both -- a lone PostToolUse event cannot credit every prior ask.
        records = [_rec("unsafe", "git push", _ts(10)),
                   _rec("unsafe", "git push", _ts(20))]
        ran_index = build_ran_index(
            [{"command": "git push", "ts": _ts(21).isoformat()}])
        approved = correlate_approvals(records, ran_index)
        self.assertEqual(len(approved), 1)

    def test_a_ran_per_prompt_approves_each(self):
        records = [_rec("unsafe", "git push", _ts(10)),
                   _rec("unsafe", "git push", _ts(20))]
        ran_index = build_ran_index([
            {"command": "git push", "ts": _ts(11).isoformat()},
            {"command": "git push", "ts": _ts(21).isoformat()},
        ])
        approved = correlate_approvals(records, ran_index)
        self.assertEqual(approved, {0, 1})

    def test_ran_within_skew_before_prompt_counts(self):
        # cutoff = prompt - 5s; a ran 3s earlier still correlates.
        records = [_rec("unknown", "git push", _ts(10))]
        ran_index = build_ran_index(
            [{"command": "git push", "ts": _ts(7).isoformat()}])
        self.assertEqual(correlate_approvals(records, ran_index), {0})

    def test_ran_well_before_prompt_is_not_approved(self):
        records = [_rec("unsafe", "git push", _ts(10))]
        ran_index = build_ran_index(
            [{"command": "git push", "ts": _ts(1).isoformat()}])
        self.assertEqual(correlate_approvals(records, ran_index), set())

    def test_no_ran_record_is_not_approved(self):
        records = [_rec("unsafe", "git push", _ts(10))]
        self.assertEqual(correlate_approvals(records, {}), set())

    def test_far_future_ran_does_not_backcredit_old_prompt(self):
        # Regression (PR #47 re-review): a denied prompt at t=0 and a run
        # 30 min later (command became statically allowed, bypassing the
        # prompt) must NOT mark the old prompt approved -- the match is
        # bounded above by RAN_MATCH_WINDOW_SECONDS.
        records = [_rec("unsafe", "git push", _ts_at(0, 0))]
        ran_index = build_ran_index(
            [{"command": "git push", "ts": _ts_at(30, 0).isoformat()}])
        self.assertEqual(correlate_approvals(records, ran_index), set())

    def test_ran_inside_window_approves(self):
        # A run a few seconds after the prompt is within the window.
        records = [_rec("unsafe", "git push", _ts_at(0, 0))]
        ran_index = build_ran_index(
            [{"command": "git push", "ts": _ts_at(0, 30).isoformat()}])
        self.assertEqual(correlate_approvals(records, ran_index), {0})

    def test_safe_records_are_never_approval_candidates(self):
        # `safe` is auto-allowed (no prompt); its ran-record must not be
        # mistaken for prompt approval.
        records = [_rec("safe", "ls here", _ts(10))]
        ran_index = build_ran_index(
            [{"command": "ls here", "ts": _ts(11).isoformat()}])
        self.assertEqual(correlate_approvals(records, ran_index), set())


class TestBuildGroups(unittest.TestCase):

    def _build(self, records, ran_index=None, min_fires=3, min_fires_safe=10):
        retval = build_groups(records, ran_index or {}, min_fires,
                              min_fires_safe)
        return retval

    def test_decision_maps_to_bucket_and_respects_friction_threshold(self):
        records = [_rec("unsafe", "rm thing", _ts(i)) for i in range(3)]
        suggestions, _ = self._build(records)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["kind"], KIND_UNSAFE)
        self.assertEqual(suggestions[0]["fires"], 3)

    def test_below_threshold_is_dropped(self):
        records = [_rec("unsafe", "rm thing", _ts(i)) for i in range(2)]
        suggestions, _ = self._build(records)
        self.assertEqual(suggestions, [])

    def test_fastpath_uses_higher_threshold(self):
        records = [_rec("safe", "ls here", _ts(i)) for i in range(9)]
        suggestions, _ = self._build(records)
        self.assertEqual(suggestions, [])
        records.append(_rec("safe", "ls here", _ts(9)))
        suggestions, _ = self._build(records)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["kind"], KIND_FASTPATH)

    def test_approved_count_is_correlated(self):
        records = [_rec("unsafe", "kubectl delete pod x", _ts(s))
                   for s in (10, 20, 30)]
        ran_index = build_ran_index([
            {"command": "kubectl delete pod x", "ts": _ts(11).isoformat()},
            {"command": "kubectl delete pod x", "ts": _ts(21).isoformat()},
        ])
        suggestions, _ = self._build(records, ran_index)
        self.assertEqual(suggestions[0]["fires"], 3)
        self.assertEqual(suggestions[0]["approved"], 2)

    def test_unknown_on_known_cli_is_upstream_candidate(self):
        records = [_rec("unknown", "kubectl rollout status x", _ts(i))
                   for i in range(3)]
        suggestions, _ = self._build(records)
        self.assertTrue(suggestions[0]["upstream_candidate"])

    def test_unknown_on_personal_tool_is_not_upstream_candidate(self):
        records = [_rec("unknown", "myinternaltool sync now", _ts(i))
                   for i in range(3)]
        suggestions, _ = self._build(records)
        self.assertFalse(suggestions[0]["upstream_candidate"])

    def test_fastpath_collision_sourced_from_other_buckets(self):
        # A safe `gh api ...` and an unsafe `gh api -X POST ...` both group
        # under prefix "gh api". The fastpath suggestion must carry the
        # collision so it is never written to settings.json.
        records = [_rec("safe", "gh api /repos/x", _ts(i)) for i in range(10)]
        records += [_rec("unsafe", "gh api -X POST /repos/x", _ts(20 + i))
                    for i in range(3)]
        suggestions, _ = self._build(records)
        fastpath = [s for s in suggestions if s["kind"] == KIND_FASTPATH]
        self.assertEqual(len(fastpath), 1)
        self.assertEqual(fastpath[0]["prefix"], "gh api")
        self.assertIn("gh api -X POST /repos/x",
                      fastpath[0]["glob_collisions"])

    def test_friction_unknown_readonly_does_not_self_collide(self):
        # Regression (PR #47 review): a repeated read-only `unknown`
        # command must keep its settings.json route. Its examples are in
        # the nonsafe set, but they are this group's own commands, so the
        # glob must not veto itself.
        records = [_rec("unknown", "kubectl get pods foo", _ts(i))
                   for i in range(3)]
        suggestions, _ = self._build(records)
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["glob_collisions"], [])

    def test_compound_friction_is_counted_not_suggested(self):
        records = [_rec("unsafe", "cat x | grep y", _ts(i)) for i in range(3)]
        suggestions, stats = self._build(records)
        self.assertEqual(suggestions, [])
        self.assertEqual(stats["compound_friction"], 3)

    def test_broken_install_records_are_tallied(self):
        records = [_rec("import-error", ""), _rec("rules-validation-error", "")]
        suggestions, stats = self._build(records)
        self.assertEqual(suggestions, [])
        self.assertEqual(stats["broken_install"], 2)

    def test_per_bucket_cap_is_enforced(self):
        records = []
        for n in range(MAX_PER_BUCKET + 2):
            command = "cli{} go".format(n)
            records += [_rec("safe", command, _ts(0)) for _ in range(10)]
        suggestions, stats = self._build(records)
        fastpath = [s for s in suggestions if s["kind"] == KIND_FASTPATH]
        self.assertEqual(len(fastpath), MAX_PER_BUCKET)
        self.assertEqual(stats["dropped_over_cap"], 2)


class TestStateMerge(unittest.TestCase):

    def test_applied_and_dismissed_status_survive_regeneration(self):
        old_state = {
            "suggestions": [
                {"id": "aaa", "status": "dismissed"},
                {"id": "bbb", "status": "applied"},
                {"id": "ccc", "status": "pending"},
            ],
        }
        new_suggestions = [
            {"id": "aaa", "status": "pending"},
            {"id": "bbb", "status": "pending"},
            {"id": "ddd", "status": "pending"},
        ]
        merged = merge_state(old_state, new_suggestions, {"records": 5})
        by_id = {s["id"]: s["status"] for s in merged["suggestions"]}
        self.assertEqual(by_id["aaa"], "dismissed")
        self.assertEqual(by_id["bbb"], "applied")
        self.assertEqual(by_id["ddd"], "pending")
        # A suggestion that no longer regenerates is dropped.
        self.assertNotIn("ccc", by_id)
        self.assertEqual(merged["version"], STATE_VERSION)
        self.assertIsNotNone(merged["generated"])

    def test_merge_serializes_datetime_stats(self):
        merged = merge_state({}, [], {"first_ts": _ts(0), "records": 1})
        self.assertEqual(merged["stats"]["first_ts"], _ts(0).isoformat())

    def test_load_state_missing_returns_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = load_state(Path(tmp) / "absent.json")
        self.assertEqual(state["version"], STATE_VERSION)
        self.assertEqual(state["suggestions"], [])

    def test_load_state_corrupt_returns_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suggestions.json"
            path.write_text("{ not valid json", encoding="utf-8")
            state = load_state(path)
        self.assertEqual(state["suggestions"], [])

    def test_load_state_valid_round_trips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suggestions.json"
            payload = {"version": STATE_VERSION, "suggestions":
                       [{"id": "x", "status": "applied"}]}
            path.write_text(json.dumps(payload), encoding="utf-8")
            state = load_state(path)
        self.assertEqual(state["suggestions"][0]["id"], "x")


class TestOverrideFragment(unittest.TestCase):
    """The minimal `commands.<cli>` spec the writer derives (issue #45)."""

    def test_single_subcommand_is_top_level_safe(self):
        self.assertEqual(
            build_override_fragment(["status"]),
            {"default": "subcommand", "safe_subcommands": ["status"]})

    def test_two_subcommands_nest_under_the_group(self):
        self.assertEqual(
            build_override_fragment(["db", "status"]),
            {"default": "subcommand",
             "nested_subcommand": {"db": {"safe_subcommands": ["status"]}}})


class TestComputeOverride(unittest.TestCase):
    """Eligibility: only a personal CLI with a subcommand is writable."""

    KNOWN = {"git", "kubectl", "aws"}

    def test_personal_cli_with_subcommand_is_writable(self):
        override = compute_override("mycli status", self.KNOWN)
        self.assertTrue(override["writable"])
        self.assertEqual(override["cli"], "mycli")
        self.assertEqual(override["label"], "commands.mycli")
        self.assertEqual(override["fragment"],
                         {"default": "subcommand", "safe_subcommands": ["status"]})

    def test_personal_cli_nested_label_and_fragment(self):
        override = compute_override("mytool db status", self.KNOWN)
        self.assertTrue(override["writable"])
        self.assertEqual(override["label"],
                         "commands.mytool.nested_subcommand.db")
        self.assertEqual(
            override["fragment"],
            {"default": "subcommand",
             "nested_subcommand": {"db": {"safe_subcommands": ["status"]}}})

    def test_known_cli_is_not_writable_and_says_why(self):
        override = compute_override("git frobnicate", self.KNOWN)
        self.assertFalse(override["writable"])
        self.assertIn("bundled rules", override["reason"])

    def test_bare_command_without_subcommand_is_not_writable(self):
        override = compute_override("mycli", self.KNOWN)
        self.assertFalse(override["writable"])
        self.assertIn("no subcommand", override["reason"])

    def test_none_known_clis_disables_writability(self):
        # Rules unavailable: cannot confirm personal-ness, so never offer to
        # write (a bundled CLI must not be mistaken for a personal one).
        override = compute_override("mycli status", None)
        self.assertFalse(override["writable"])

    def test_load_known_clis_includes_bundled_commands(self):
        known = load_known_clis(RULES_DIR)
        self.assertIsNotNone(known)
        for name in ("git", "gh", "aws", "python3"):
            self.assertIn(name, known)


class TestMergeCommandFragment(unittest.TestCase):

    def test_into_empty_spec(self):
        merged = merge_command_fragment(
            {}, {"default": "subcommand", "safe_subcommands": ["status"]})
        self.assertEqual(
            merged, {"default": "subcommand", "safe_subcommands": ["status"]})

    def test_unions_without_dropping_existing_subcommands(self):
        merged = merge_command_fragment(
            {"default": "subcommand", "safe_subcommands": ["show"]},
            {"default": "subcommand", "safe_subcommands": ["status"]})
        self.assertEqual(merged["safe_subcommands"], ["show", "status"])

    def test_is_idempotent(self):
        existing = {"default": "subcommand", "safe_subcommands": ["status"]}
        merged = merge_command_fragment(
            existing, {"default": "subcommand", "safe_subcommands": ["status"]})
        self.assertEqual(merged["safe_subcommands"], ["status"])

    def test_preserves_unrelated_keys(self):
        merged = merge_command_fragment(
            {"default": "subcommand", "unsafe_subcommands": ["apply"]},
            {"default": "subcommand", "safe_subcommands": ["status"]})
        self.assertEqual(merged["unsafe_subcommands"], ["apply"])
        self.assertEqual(merged["safe_subcommands"], ["status"])

    def test_nested_union_preserves_other_groups(self):
        existing = {
            "default": "subcommand",
            "nested_subcommand": {"vol": {"safe_subcommands": ["ls"]}}}
        merged = merge_command_fragment(
            existing,
            {"default": "subcommand",
             "nested_subcommand": {"db": {"safe_subcommands": ["status"]}}})
        self.assertEqual(merged["nested_subcommand"]["vol"]["safe_subcommands"],
                         ["ls"])
        self.assertEqual(merged["nested_subcommand"]["db"]["safe_subcommands"],
                         ["status"])

    def test_does_not_mutate_caller(self):
        existing = {"default": "subcommand", "safe_subcommands": ["show"]}
        merge_command_fragment(
            existing, {"default": "subcommand", "safe_subcommands": ["status"]})
        self.assertEqual(existing["safe_subcommands"], ["show"])


class TestBuildGroupsOverride(unittest.TestCase):
    """friction-unknown suggestions carry the override-routing decision."""

    def test_personal_cli_unknown_is_override_writable(self):
        records = [_rec("unknown", "mycli status now", _ts(i)) for i in range(3)]
        suggestions, _ = build_groups(records, {}, 3, 10, known_clis={"git"})
        unknown = [s for s in suggestions if s["kind"] == KIND_UNKNOWN]
        self.assertEqual(len(unknown), 1)
        self.assertTrue(unknown[0]["override"]["writable"])
        self.assertEqual(unknown[0]["override"]["cli"], "mycli")

    def test_known_cli_unknown_is_not_override_writable(self):
        records = [_rec("unknown", "kubectl rollout status x", _ts(i))
                   for i in range(3)]
        suggestions, _ = build_groups(records, {}, 3, 10,
                                      known_clis={"kubectl"})
        unknown = [s for s in suggestions if s["kind"] == KIND_UNKNOWN]
        self.assertFalse(unknown[0]["override"]["writable"])

    def test_non_unknown_buckets_have_no_override(self):
        records = [_rec("unsafe", "rm thing", _ts(i)) for i in range(3)]
        suggestions, _ = build_groups(records, {}, 3, 10, known_clis=set())
        self.assertNotIn("override", suggestions[0])


def _seed_state(state_dir, suggestions):
    state = {
        "version": STATE_VERSION, "generated": None, "last_nudged": None,
        "stats": {}, "suggestions": suggestions,
    }
    save_state(Path(state_dir) / STATE_NAME, state)


def _write_args(ids, tmp, state_dir, shell_override):
    return SimpleNamespace(
        ids=list(ids), state_dir=str(state_dir),
        shell_override=str(shell_override), rules_dir=str(RULES_DIR),
        log=str(Path(tmp) / "yolt.log"), ran_log=str(Path(tmp) / "ran.log"))


def _run_write(args):
    """Call cmd_write_override capturing its stdout/stderr so the test log
    stays clean. Returns (rc, stderr_text)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cmd_write_override(args)
    return rc, err.getvalue()


def _writable_suggestion(prefix, known):
    sid = suggestion_id(KIND_UNKNOWN, prefix)
    return {
        "id": sid, "kind": KIND_UNKNOWN, "prefix": prefix, "fires": 4,
        "approved": 0, "status": "pending",
        "settings_pattern": "Bash({}*)".format(prefix),
        "glob_collisions": [], "examples": ["{} --json".format(prefix)],
        "override": compute_override(prefix, known),
    }


class TestWriteOverride(unittest.TestCase):
    """End-to-end `--write-override`: read-modify-write + validate-before-write
    against the real bundled rules (issue #45)."""

    def test_writes_fragment_and_marks_applied(self):
        known = load_known_clis(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            sug = _writable_suggestion("mycli status", known)
            _seed_state(state_dir, [sug])

            rc, _ = _run_write(
                _write_args([sug["id"]], tmp, state_dir, shell_override))

            self.assertEqual(rc, 0)
            written = json.loads(shell_override.read_text())
            self.assertEqual(
                written["commands"]["mycli"],
                {"default": "subcommand", "safe_subcommands": ["status"]})
            state = load_state(state_dir / STATE_NAME)
            self.assertEqual(state["suggestions"][0]["status"], "applied")

    def test_written_override_loads_and_classifies_via_hook(self):
        # The whole point: the written file must validate and take effect when
        # the classifier loads default rules ∪ this override.
        from grammar_classifier import classify_command  # noqa: E402
        from rule_classifier import load_shell_rules  # noqa: E402
        known = load_known_clis(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            sug = _writable_suggestion("mycli status", known)
            _seed_state(state_dir, [sug])
            _run_write(
                _write_args([sug["id"]], tmp, state_dir, shell_override))

            rules = load_shell_rules(RULES_DIR,
                                     user_overrides_path=shell_override,
                                     validate=True)
            decision, _ = classify_command("mycli status", rules)
            self.assertEqual(decision, "safe")
            other, _ = classify_command("mycli apply", rules)
            self.assertEqual(other, "unknown")  # additive: apply still prompts

    def test_preserves_existing_unrelated_commands(self):
        known = load_known_clis(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            shell_override.write_text(json.dumps(
                {"commands": {"othertool": {"default": "safe"}}}))
            sug = _writable_suggestion("mycli status", known)
            _seed_state(state_dir, [sug])

            _run_write(
                _write_args([sug["id"]], tmp, state_dir, shell_override))

            written = json.loads(shell_override.read_text())
            self.assertEqual(written["commands"]["othertool"],
                             {"default": "safe"})
            self.assertIn("mycli", written["commands"])

    def test_invalid_preexisting_override_is_refused_untouched(self):
        known = load_known_clis(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            payload = {"totally_bogus_key": 1}
            shell_override.write_text(json.dumps(payload))
            sug = _writable_suggestion("mycli status", known)
            _seed_state(state_dir, [sug])

            rc, err = _run_write(
                _write_args([sug["id"]], tmp, state_dir, shell_override))

            self.assertEqual(rc, 1)
            self.assertIn("fail validation", err)
            # File untouched and suggestion not marked applied.
            self.assertEqual(json.loads(shell_override.read_text()), payload)
            state = load_state(state_dir / STATE_NAME)
            self.assertEqual(state["suggestions"][0]["status"], "pending")

    def test_not_writable_id_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            sug = _writable_suggestion("git frobnicate", {"git"})
            self.assertFalse(sug["override"]["writable"])
            _seed_state(state_dir, [sug])

            rc, err = _run_write(
                _write_args([sug["id"]], tmp, state_dir, shell_override))

            self.assertEqual(rc, 1)
            self.assertIn("not override-writable", err)
            self.assertFalse(shell_override.exists())

    def test_unknown_id_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            _seed_state(state_dir, [])

            rc, err = _run_write(
                _write_args(["deadbeef"], tmp, state_dir, shell_override))

            self.assertEqual(rc, 1)
            self.assertIn("unknown id", err)
            self.assertFalse(shell_override.exists())

    def test_two_ids_same_cli_union_into_one_spec(self):
        known = load_known_clis(RULES_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            state_dir.mkdir()
            shell_override = Path(tmp) / "shell.json"
            s1 = _writable_suggestion("mycli status", known)
            s2 = _writable_suggestion("mycli show", known)
            _seed_state(state_dir, [s1, s2])

            rc, _ = _run_write(
                _write_args([s1["id"], s2["id"]], tmp, state_dir,
                            shell_override))

            self.assertEqual(rc, 0)
            written = json.loads(shell_override.read_text())
            self.assertEqual(
                sorted(written["commands"]["mycli"]["safe_subcommands"]),
                ["show", "status"])


if __name__ == "__main__":
    unittest.main()
