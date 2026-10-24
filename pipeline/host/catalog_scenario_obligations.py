#!/usr/bin/env python3
"""Static source/suite obligations for the existing adapter catalog and traces.

Never executes Make, shell, OpenSSH, compilers or privileged setup. Native
scenario success remains separate from library-call or interpreted coverage.
"""
import hashlib
import json
from pathlib import Path
import re

PROFILES = {
    "openssl": ["WITH_OPENSSL"], "compression": ["WITH_ZLIB"],
    "pam": ["USE_PAM"], "kerberos": ["KRB5"], "gssapi": ["GSSAPI"],
    "selinux": ["WITH_SELINUX"], "linux-audit": ["USE_LINUX_AUDIT"],
    "bsm-audit": ["USE_BSM_AUDIT"], "line-editing": ["USE_LIBEDIT"],
    "pkcs11": ["ENABLE_PKCS11"], "external-security-key": ["ENABLE_SK"],
    "builtin-fido": ["ENABLE_SK_INTERNAL"],
    "linux-seccomp": ["SANDBOX_SECCOMP_FILTER"],
    "capsicum-sandbox": ["SANDBOX_CAPSICUM"], "darwin-sandbox": ["SANDBOX_DARWIN"],
    "solaris-sandbox": ["SANDBOX_SOLARIS"], "rlimit-sandbox": ["SANDBOX_RLIMIT"],
    "null-sandbox": ["SANDBOX_NULL"], "bsd-auth": ["BSD_AUTH"],
    "aix-auth": ["WITH_AIXAUTHENTICATE"], "osf-sia": ["HAVE_OSF_SIA"],
    "cygwin": ["HAVE_CYGWIN"], "wtmpdb": ["USE_WTMPDB"],
}
# Reviewed associations, not a generated call graph or proof of path coverage.
# Every unmapped upstream test remains an independent inventory obligation.
FEATURES = [
    ("transport-algorithms", "try-ciphers kextype keytype rekey integrity proto-version proto-mismatch",
     "packet.c kex.c cipher.c", "loopback-command ssh-query-cipher ssh-query-kex ssh-query-key ssh-query-mac",
     "Force each configured cipher/MAC/KEX/key combination where applicable; rekey and malformed transport paths."),
    ("forwarding-multiplex-proxy", "forwarding dynamic-forward forward-control multiplex proxy-connect proxyjump",
     "channels.c mux.c sshconnect.c", "",
     "Local/remote/dynamic/Unix-socket forwarding, denial, descriptor passing, control commands, ProxyCommand and ProxyJump."),
    ("terminal-and-signals", "ssh-tty exit-status-signal",
     "sshpty.c sshtty.c ttymodes.c session.c", "",
     "PTY creation, terminal modes, window changes, interactive escape/termination, job control and signals."),
    ("authentication-methods", "password kbdint hostbased multipubkey allow-deny-users",
     "auth-passwd.c auth-shadow.c auth2-kbdint.c auth2-hostbased.c", "loopback-command loopback-denied-key loopback-denied-none loopback-denied-unknown-user",
     "Password/expiry, keyboard interactive, hostbased and multi-method authentication, distinct account policy outcomes."),
    ("certificates-host-trust", "cert-hostkey cert-userkey principals-command krl knownhosts hostkey-rotate hostkey-agent cert-file",
     "auth2-pubkey.c auth2-pubkeyfile.c hostfile.c krl.c", "loopback-denied-host-key",
     "CA/principal/certificate constraints, time validity, revocation, host-key rotation/update and agent host keys."),
    ("configuration-and-command-hooks", "cfginclude servcfginclude cfgmatch cfgmatchlisten keys-command knownhosts-command localcommand forcecommand percent",
     "readconf.c servconf.c misc.c", "ssh-config-default ssh-config-ipv4 ssh-config-missing ssh-config-invalid-option ssh-invalid-port",
     "Include/Match/token expansion, command-generated keys/principals/known-hosts, LocalCommand, ForceCommand and rc/environment paths."),
    ("agent-restrictions", "agent agent-timeout agent-restrict agent-getpeereid agent-ptrace agent-subprocess",
     "ssh-agent.c authfd.c", "agent-add agent-sign-verify agent-remove agent-remove-all",
     "Agent expiry, locking, confirmation, destination restrictions, forwarded agents, peer identities and subprocess mode."),
    ("dynamic-crypto-providers", "ssh-pkcs11 agent-pkcs11 agent-pkcs11-restrict agent-pkcs11-cert",
     "ssh-pkcs11.c ssh-sk.c ssh-sk-client.c", "",
     "Provider loading, symbol/protocol validation, indirect callbacks, PIN failures, resident keys, provider errors and dummy/real SK profiles."),
    ("resolver-address-families", "sshfp-connect host-expand addrmatch dynamic-forward",
     "dns.c channels.c sshconnect.c", "",
     "IPv6, nonnumeric resolution/canonicalization, multi-address fallback, resolver failures and SSHFP/DNSSEC."),
    ("privileged-server-state", "connect-privsep sftp-chroot agent-getpeereid",
     "session.c uidswap.c loginrec.c sandbox-seccomp-filter.c", "",
     "Cross-user credentials/groups, chroot, ownership, login accounting, privilege separation and configured sandbox effects."),
    ("transfer-filesystem-variants", "scp scp3 scp-uri sftp sftp-chroot sftp-cmds sftp-badcmds sftp-batch sftp-glob sftp-perm sftp-resume sftp-uri",
     "sftp-client.c sftp-server.c scp.c", "loopback-scp-upload loopback-scp-download loopback-scp-legacy-upload loopback-scp-legacy-download loopback-sftp-upload loopback-sftp-download loopback-sftp-metadata loopback-sftp-missing loopback-scp-missing",
     "Recursive/resumed transfers, links/globs, permissions, extension/error variants, chroot/internal SFTP and malformed requests."),
    ("failures-and-lifecycle", "broken-pipe yes-head login-timeout channel-timeout connection-timeout penalty penalty-expire reconfigure reexec",
     "atomicio.c clientloop.c serverloop.c sshd.c", "loopback-exit-status loopback-command-stderr",
     "Controlled partial/interrupted I/O, resource exhaustion, failed creation/exec, disconnects, shutdown/restart, deadlines and penalties."),
    ("x11-and-device-tunnels", "",
     "channels.c clientloop.c openbsd-compat/port-net.c", "",
     "X11 authentication/helpers and displays, TUN/TAP device setup, privileged ioctls, failures and packet forwarding; no dedicated full execution case mapped."),
    ("child-programs", "hostbased password keys-command principals-command knownhosts-command localcommand forcecommand proxy-connect",
     "session.c readpass.c sshconnect.c ssh-keysign.c", "loopback-command loopback-stdin loopback-scp-legacy-upload",
     "ssh-keysign, askpass, configured hooks, X11 helpers and arbitrary exec targets with their own dependencies/failures."),
]

def digest(data):
    return hashlib.sha256(data).hexdigest()

def logical_lines(text):
    pending, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        pending += line
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield start, pending
        pending = ""
    if pending:
        yield start, pending + " <unterminated-continuation>"

def make_variables(text):
    """Read assignments only; Make expressions are never evaluated."""
    result = {}
    for number, line in logical_lines(text):
        match = re.match(r"^([A-Za-z_][A-Za-z_0-9]*)\s*(\+=|:=|\?=|=)\s*(.*?)\s*$", line)
        if not match:
            continue
        name, operation, value = match.groups()
        value = value.split("#", 1)[0].strip()
        if operation == "?=" and name in result:
            continue
        if operation == "+=" and name in result:
            value = result[name]["value"] + " " + value
        result[name] = {"value": value, "line": number}
    return result

def make_words(variables, name):
    problems = []
    def expand(key, seen):
        if key in seen:
            problems.append("cyclic Make variable: " + key)
            return ""
        if key not in variables:
            problems.append("unknown Make variable: " + key)
            return ""
        value = variables[key]["value"]
        value = re.sub(r"\$\(([A-Za-z_][A-Za-z_0-9]*)\)|\$\{([A-Za-z_][A-Za-z_0-9]*)\}",
                       lambda m: expand(m.group(1) or m.group(2), seen | {key}), value)
        if re.search(r"[^A-Za-z_0-9./+\s-]", value):
            problems.append("unparsed Make expression in " + key + ": " + value)
            return ""
        return value
    words = expand(name, set()).split()
    if len(set(words)) != len(words):
        problems.append("duplicate Make entries in " + name)
    return words, sorted(set(problems))

def config_macros(text):
    values, conflicts = {}, []
    for line, raw in enumerate(text.splitlines(), 1):
        enabled = re.match(r"^\s*#define\s+([A-Za-z_]\w*)(?:\s+(.*))?$", raw)
        disabled = re.match(r"^\s*/\*\s*#undef\s+([A-Za-z_]\w*)\s*\*/", raw)
        if not (enabled or disabled):
            continue
        name = (enabled or disabled).group(1)
        value = {"status": "enabled" if enabled else "disabled",
                 "line": line, "definition": raw}
        if name in values and values[name]["status"] != value["status"]:
            conflicts.append(name)
            value["status"] = "unknown-conflicting"
        values[name] = value
    return values, sorted(set(conflicts))

def prerequisite_evidence(text, path):
    """Preserve source gates, never infer that a conditional test actually ran."""
    lines = text.splitlines()
    rows = []
    for offset, line in enumerate(lines):
        if re.search(r"\bskip\b|SKIP_UNIT|SKIP_LTESTS|TEST_SSH_UTF8|maybe_filter_sk|config_defined|^\s*#\s*(?:if|ifdef|ifndef|elif)\b", line) or (not path.endswith((".c", ".h")) and re.search(r"\bif\b|\bcase\b", line) and not line.lstrip().startswith("#")):
            if line.lstrip().startswith("#") and not re.match(r"\s*#\s*(if|ifdef|ifndef|elif)\b", line):
                continue
            rows.append({"path": path, "line": offset + 1,
                         "source": "\n".join(lines[max(0, offset-3):min(len(lines), offset+2)]),
                         "condition_status": "not-evaluated", "execution_status": "not-established"})
    return rows

def build_inventory(reference, tools, scenario_plan=(), records=(), configuration_hashes=None):
    reference = Path(reference).resolve()
    issues, identities, texts = [], {}, {}
    def read(relative):
        relative = str(relative)
        path = (reference / relative).resolve()
        if not path.is_relative_to(reference):
            issues.append("source path escapes reference: " + relative)
            return ""
        if relative in texts:
            return texts[relative]
        try:
            data = path.read_bytes()
            text = data.decode("utf-8")
        except (OSError, UnicodeError) as error:
            issues.append("source unavailable: " + relative + ": " + type(error).__name__)
            return ""
        identities[relative] = digest(data)
        texts[relative] = text
        if Path(relative).name == "Makefile":
            for number, line in enumerate(text.splitlines(), 1):
                if re.match(r"^(?:ifeq|ifneq|ifdef|ifndef|include|-include|sinclude)\b", line):
                    issues.append(f"unparsed Make condition/include {relative}:{number}: {line}")
        return text

    top = make_variables(read("Makefile"))
    configured_tools, errors = make_words(top, "TARGETS")
    issues.extend(errors)
    if set(configured_tools) != set(tools):
        issues.append("configured TARGETS differ from selected catalog tools")
    configuration = read("config.h")
    macros, conflicts = config_macros(configuration)
    issues.extend("conflicting config macro: " + name for name in conflicts)
    profiles = []
    for name, required in PROFILES.items():
        entries = {key: macros.get(key, {"status":"unknown", "line":None}) for key in required}
        state = ("unknown" if any(row["status"].startswith("unknown") for row in entries.values()) else
                 "enabled" if all(row["status"] == "enabled" for row in entries.values()) else "disabled")
        profiles.append({"id": name, "status": state, "macros": entries,
                         "full_release_obligation": "unresolved-profile-behavior"})
        if state == "unknown":
            issues.append("configuration profile unresolved: " + name)
    read("version.h")
    config_matches = True
    for name, expected in (configuration_hashes or {}).items():
        read(name)
        if identities.get(name) != expected:
            issues.append("catalog configuration identity differs: " + name)
            config_matches = False

    regression = read("regress/Makefile")
    variables = make_variables(regression)
    suites = {}
    for kind, variable in (("integration", "LTESTS"), ("file", "REGRESS_TARGETS"),
                           ("interop", "INTEROP_TESTS"), ("extra", "EXTRA_TESTS")):
        names, errors = make_words(variables, variable)
        issues.extend("regress/" + error for error in errors)
        rows = []
        for name in names:
            path = "regress/" + name + ".sh" if kind != "file" else "regress/Makefile"
            source = read(path)
            rows.append({"target": name, "path": path, "source_sha256": identities.get(path),
                         "execution_status": "not-observed-by-scenario-runner",
                         "conditional_prerequisites": prerequisite_evidence(source, path),
                         "condition_status": "not-evaluated"})
        suites[kind] = rows
    # Derive unit programs from the actual invocations, not all directory names.
    unit_names = list(dict.fromkeys(re.findall(r"/unittests/([A-Za-z_0-9-]+)/test_[A-Za-z_0-9-]+", regression)))
    if not unit_names:
        issues.append("no unit invocations parsed from regress/Makefile")
    unit_rows = []
    for name in unit_names:
        folder = reference / "regress/unittests" / name
        paths = sorted(p.relative_to(reference).as_posix() for p in folder.rglob("*")
                       if p.is_file() and (p.suffix in (".c", ".h") or p.name.startswith("Makefile")))
        if not paths:
            issues.append("unit source unavailable: " + name)
        gates = []
        for path in paths:
            gates.extend(prerequisite_evidence(read(path), path))
        unit_rows.append({"target": "test_" + name, "directory": str(folder.relative_to(reference)),
                          "sources": paths, "conditional_prerequisites": gates,
                          "execution_status": "not-observed-by-scenario-runner",
                          "condition_status": "not-evaluated"})
    suites["unit"] = unit_rows
    compat_path = "openbsd-compat/regress/Makefile"
    compat_vars = make_variables(read(compat_path))
    compat, errors = make_words(compat_vars, "TESTPROGS")
    issues.extend("compat/" + error for error in errors)
    suites["compat"] = []
    for name in compat:
        path = "openbsd-compat/regress/" + name + ".c"
        source = read(path)
        suites["compat"].append({"target": name, "path": path, "source_sha256": identities.get(path),
                                 "conditional_prerequisites": prerequisite_evidence(source, path),
                                 "execution_status": "not-observed-by-scenario-runner",
                                 "condition_status": "not-evaluated"})
    shared_gates = []
    for path in ("regress/Makefile", "regress/test-exec.sh", "Makefile", "regress/README.regress"):
        shared_gates.extend(prerequisite_evidence(read(path), path))
    # Other conditional Make tests and extension lists are not silently dropped.
    for key in ("OTHERTESTS",):
        if key in compat_vars:
            value, errors = make_words(compat_vars, key)
            issues.extend(errors)
            if value:
                issues.append("additional compat targets require classification: " + " ".join(value))

    plan = {row["id"]: row for row in scenario_plan}
    if len(plan) != len(scenario_plan):
        issues.append("duplicate scenario identifiers")
    entries = list(records.values()) if isinstance(records, dict) else list(records)
    record_map = {row["id"]: row for row in entries}
    if len(record_map) != len(entries):
        issues.append("duplicate scenario receipts")
    observed = {}
    for key, row in record_map.items():
        declared = plan.get(key)
        if declared is None or row.get("tool") != declared.get("tool"):
            issues.append("receipt does not match a planned scenario: " + key)
            continue
        expected = tools.get(row["tool"], {}).get("sha256")
        identity = expected and row.get("binary_sha256") == expected
        actual = (identity and config_matches and row.get("native_execution") is True and
                  row.get("original_binary_exec_observed") is True)
        if not actual:
            continue
        observed[key] = row
    selected_tools = []
    for name, tool in sorted(tools.items()):
        matching = [key for key, row in observed.items() if row["tool"] == name]
        selected_tools.append({"tool": name, "sha256": tool.get("sha256"),
                               "configured": name in configured_tools,
                               "planned_scenarios": sorted(key for key, row in plan.items() if row["tool"] == name),
                               "native_observed_scenarios": sorted(matching),
                               "native_passed_scenarios": sorted(key for key in matching if observed[key].get("status") == "passed"),
                               "status": "native-invocation-observed" if matching else "untraced",
                               "library_api_coverage": None})
    upstream_names = {row["target"] for rows in suites.values() for row in rows}
    features = []
    for key, tests, sources, related, gap in FEATURES:
        for source in sources.split():
            read(source)
        relevant = related.split()
        unknown_tests = sorted(set(tests.split()) - upstream_names)
        if unknown_tests:
            issues.append("feature " + key + " has unknown upstream targets: " + ", ".join(unknown_tests))
        successes = sorted(name for name in relevant if name in observed and observed[name].get("status") == "passed")
        features.append({"id": key, "required_source_paths": sources.split(), "upstream_targets": tests.split(),
                         "related_planned_scenarios": sorted(set(relevant) & plan.keys()),
                         "native_passed_related_scenarios": successes,
                         "observation_status": "partial-native-observation" if successes else "unexercised-by-recorded-plan",
                         "remaining_obligation": gap, "library_api_coverage": None,
                         "coverage_complete": False})
    reasons = ["finite scenarios do not establish all behavior or error paths",
               "library-call coverage is unmeasured",
               "upstream suite executions and conditional prerequisites are not established",
               "disabled/alternate configuration profiles remain full-release obligations",
               "indirect callbacks, providers, child programs and transitive dependencies remain open"]
    if issues:
        reasons.append("inventory has unresolved or unparsed inputs")
    inventory = {
        "schema": 1, "scope": "source/configuration/scenario inventory, not execution or equivalence proof",
        "source_root": str(reference), "source_hashes": dict(sorted(identities.items())),
        "parser_sha256": digest(Path(__file__).read_bytes()),
        "source_hash_scope": "current original source bytes and configured Makefiles; does not independently authenticate their Git revision or hash all runtime test data",
        "configuration_profiles": profiles,
        "configuration_macro_inventory": macros,
        "configuration_scope": "macro definitions are inventory evidence; arbitrary preprocessor conditions and platform behavior are not evaluated",
        "selected_tools": selected_tools,
        "observation_scope": "only supplied native receipts; absence does not assert a tool was never run",
        "scenario_counts": {"distinct_planned": len(plan), "recorded": len(record_map),
                            "native_identity_matched": len(observed),
                            "native_passed": sum(row.get("status") == "passed" for row in observed.values())},
        "upstream_suites": suites, "shared_conditional_prerequisites": shared_gates,
        "upstream_counts": {key:len(value) for key,value in suites.items()},
        "feature_obligations": features, "unresolved_inputs": sorted(set(issues)),
        "library_api_coverage": None,
        "completeness": {"claim": False, "status": "incomplete", "reasons": reasons},
    }
    return inventory

def markdown(inventory):
    lines = ["", "## Source and scenario obligations", "",
             "These counts describe source targets and native invocations, not API or behavioral coverage.", "",
             "| Tool | Native observation | Planned scenarios | Passed native scenarios |",
             "| --- | --- | ---: | ---: |"]
    for row in inventory["selected_tools"]:
        lines.append(f"| {row['tool']} | {row['status']} | {len(row['planned_scenarios'])} | {len(row['native_passed_scenarios'])} |")
    lines += ["", "| Original suite | Targets/programs | Execution evidence |", "| --- | ---: | --- |"]
    for name, count in inventory["upstream_counts"].items():
        lines.append(f"| {name} | {count} | not established by scenario runner |")
    lines += ["", "| Feature | Related native evidence | Remaining obligation |", "| --- | --- | --- |"]
    for row in inventory["feature_obligations"]:
        lines.append(f"| {row['id']} | {row['observation_status']} | {row['remaining_obligation']} |")
    lines += ["", "C library API coverage: unmeasured. Completeness: **not established**.", "",
              "Configuration profiles, exact source hashes and unevaluated prerequisite excerpts are retained in JSON."]
    if inventory["unresolved_inputs"]:
        lines += ["", "Unresolved inventory inputs:"] + ["- " + item for item in inventory["unresolved_inputs"]]
    return lines

def aggregate_completeness(*inventories):
    """One conjunctive catalog status; absence of another inventory stays open."""
    reasons = [] if inventories else ["no inventories supplied"]
    for name, inventory in inventories:
        claim = inventory.get("completeness", {}).get("claim") if isinstance(inventory, dict) else None
        if claim is not True:
            reasons.append(name + ": " + ("incomplete" if claim is False else "not established"))
    return {"claim": not reasons, "status": "incomplete" if reasons else "complete",
            "reasons": reasons}
