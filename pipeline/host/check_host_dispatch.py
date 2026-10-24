#!/usr/bin/env python3
"""Prepare hash-bound Cabs/libc model inputs. The historical host runner is retired."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--build-receipt-sha256", required=True)
    ap.add_argument("--fuel", type=int, required=True)
    ap.add_argument("--ssh-inputs-only", action="store_true", help="Prepare analysis inputs; never run OpenSSH in Lean")
    args = ap.parse_args()
    if not args.ssh_inputs_only:
        ap.error("Host execution is retired; only --ssh-inputs-only remains")
    require(sys.platform == "linux" and args.fuel > 0, "Run in WSL with positive explicit fuel")
    root = args.workspace.resolve(strict=True)
    sys.path.insert(0, str(root / "work"))
    import build_guard
    from run_pointer_check_plan import check_build
    scripts = root / "outputs/openssh-lean/scripts"
    sys.path.insert(0, str(scripts))
    import ssh_startup_inputs
    from varargs_publication import identity_snapshot
    sys.path.insert(0, str(root / "work/cerberus-lean/scripts"))
    from process_scope import ProcessScope
    runtime = build_guard.RUNTIME
    out = args.output.absolute()
    require(out.parent == runtime and out.resolve() == out and not out.exists(),
            "Use a fresh, unaliased direct child of the project runtime directory")
    repo = runtime / "cerberus-lean"
    parser = repo / "_build/default/backend/driver/main.exe"
    installed = repo / "_build/install/default"
    capped = root / "work/cerberus-lean/scripts/capped"
    env = dict(os.environ, LEAN_CC="/usr/bin/cc", CERB_MEM_MAX="none",
               LEAN_NUM_THREADS="1", LEAN_ABORT_ON_PANIC="1")
    env["PATH"] = str(root / "work/lean-4.32.2-linux/bin") + os.pathsep + env.get("PATH", "")
    env.pop("LEAN_PATH", None)
    with open(os.devnull, "rb") as null:
        os.dup2(null.fileno(), 0)
    with build_guard.workflow_lock():
        build_guard.verify_tools()
        build = check_build(root, runtime, args.build_receipt_sha256)
        out.mkdir()
        report = dict(schema=1, terminal=False, passed=False, mode="ssh-inputs-only",
            scope="Configured Cabs/libc input provenance only; no program execution or equivalence proof",
            build_receipt_sha256=args.build_receipt_sha256, build_outputs=build["outputs"], fuel=args.fuel,
            steps=[], input_provenance_only=True, linked_core_certified=False,
            linked_execution_verified=False, behavioral_equivalence_proved=False,
            ssh_startup=dict(requested=True, passed=False, status="not-attempted", behavioral_equivalence_proved=False))
        artifacts = {}
        def save():
            build_guard.save(out / "result.json", report)
        def freeze(path):
            artifacts[str(path)] = sha(path)
        def read(row, stream):
            return Path(row[stream]["path"]).read_bytes()
        def clean(row):
            return (not row["residual_processes"] and row["exit_code"] >= 0 and
                    not any(text in read(row, "stderr") for text in
                            (b"capped: OOM-KILLED", b"capped: KILLED", b"capped: ERROR")))
        def input_identity():
            files = [Path(__file__), scripts / "ssh_startup_inputs.py", scripts / "preprocessed_input.py",
                     root / "work/build_guard.py", root / "work/run_pointer_check_plan.py",
                     root / "work/toolchain-lock.json", parser,
                     root / "work/cerberus-lean/scripts/prepare_gnu_amd64_libc.py",
                     root / "work/cerberus-lean/scripts/process_scope.py", capped]
            return dict(runtime=identity_snapshot(repo), files={str(p): sha(p) for p in files})

        def run(label, argv, cwd=out, stdout_path=None, extra_env=None):
            argv = [str(value) for value in argv]
            stdout_path = stdout_path or out / (label + ".stdout")
            stderr_path = out / (label + ".stderr")
            scope_path = out / (label + "-lifetime")
            start = time.monotonic()
            row = {"label": label, "argv": argv, "cwd": str(cwd),
                   "scoped_argv": [str(capped), *argv], "lifetime_receipt": str(scope_path / "scope.json")}
            print(label, flush=True)
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                scope = ProcessScope(scope_path)
                try:
                    build_guard.record_child(scope.guardian)
                    child_env = env if extra_env is None else dict(env, **extra_env)
                    if extra_env is not None:
                        row["additional_environment"] = extra_env
                    proc = scope.start(row["scoped_argv"], cwd=cwd, env=child_env, stdout=stdout, stderr=stderr)
                    build_guard.record_child(proc)
                    row["exit_code"] = scope.wait(None)
                finally:
                    row["residual_processes"] = scope.finish(
                        cancel=scope.proc is None or scope.proc.poll() is None)
            row["seconds"] = round(time.monotonic() - start, 3)
            for stream, path in (("stdout", stdout_path), ("stderr", stderr_path)):
                row[stream] = {"path": str(path), "sha256": sha(path), "bytes": path.stat().st_size}
                freeze(path)
            report["steps"].append(row)
            save()
            return row

        def check_ssh_startup():
            row = report["ssh_startup"]
            row["status"] = "preparing-inputs"
            plan = ssh_startup_inputs.load_inputs(root, runtime, parser)
            row["inputs"] = plan
            artifacts.update(plan["input_files"])
            save()
            folder = out / "ssh-startup"
            folder.mkdir()
            cabs = []
            row["cabs_inputs"] = []
            for index, unit in enumerate(plan["units"]):
                cached = unit["cached_cabs"]
                if cached is not None:
                    path = Path(cached)
                    producer = "verified-current-parser-cache"
                else:
                    path = folder / f"{index:03d}-{Path(unit['source']).stem}.cabs.json"
                    parsed = run(f"ssh-cabs-{index:03d}",
                        ssh_startup_inputs.cabs_arguments(parser, installed, plan["cpp_adapter"], unit["preprocessed"]),
                        stdout_path=path)
                    require(clean(parsed) and parsed["exit_code"] == 0 and path.stat().st_size > 0,
                            f"ssh Cabs export failed: {unit['source']}")
                    producer = parsed["label"]
                freeze(path)
                cabs.append(path)
                row["cabs_inputs"].append({"source": unit["source"], "path": str(path),
                                          "sha256": artifacts[str(path)], "producer": producer})
                save()
            preparer = root / "work/cerberus-lean/scripts/prepare_gnu_amd64_libc.py"
            profile = runtime / "gnu-amd64-libc-profile"
            if not ssh_startup_inputs.profile_is_current(profile, repo, preparer):
                profile = folder / "libc-profile"
                prepared = run("ssh-libc-profile", [sys.executable, preparer,
                    "--repository", repo, "--output", profile, "--gnu-pointer-conversions", "--timeout", "0"])
                require(clean(prepared) and prepared["exit_code"] == 0,
                        "ssh physical-va_list libc preparation failed")
            require(ssh_startup_inputs.profile_is_current(profile, repo, preparer),
                    "ssh libc profile is not bound to current producer/inputs")
            profile_data = json.loads((profile / "profile.json").read_bytes())
            freeze(profile / "profile.json")
            for name in profile_data["artifact_sha256"]:
                freeze(profile / name)
            for name, digest in profile_data["before"]["inputs"].items():
                artifacts[str(repo / name)] = digest
            row["libc_profile"] = {"path": str(profile / "profile.json"),
                                    "sha256": artifacts[str(profile / "profile.json")],
                                    "engine_verified": False}
            check_build(root, runtime, args.build_receipt_sha256)
            row["status"] = "inputs-prepared"
            row["input_provenance_prepared"] = True
            save()

        try:
            report["identity_before"] = input_identity()
            save()
            check_ssh_startup()
        except Exception as error:
            report["error"] = str(error)
        finally:
            try:
                check_build(root, runtime, args.build_receipt_sha256)
                report["identity_after"] = input_identity()
                if "libc_profile" in report["ssh_startup"]:
                    require(ssh_startup_inputs.profile_is_current(
                        Path(report["ssh_startup"]["libc_profile"]["path"]).parent, repo,
                        root / "work/cerberus-lean/scripts/prepare_gnu_amd64_libc.py"),
                        "Libc profile identity changed during input preparation")
                report["artifact_hashes_before"] = artifacts
                report["artifact_hashes_after"] = {path: sha(path) for path in artifacts}
                report["artifact_hashes_verified"] = (
                    report.get("identity_before") == report["identity_after"] and
                    report["artifact_hashes_before"] == report["artifact_hashes_after"])
                report["passed"] = ("error" not in report and report["artifact_hashes_verified"] and
                    report["ssh_startup"].get("input_provenance_prepared") is True and
                    report["ssh_startup"]["status"] == "inputs-prepared" and
                    report["ssh_startup"]["passed"] is False and
                    not any(row["label"].startswith("ssh-version-") for row in report["steps"]))
            except Exception as error:
                report["identity_error"] = str(error)
                report["passed"] = False
            report["terminal"] = True
            save()
        print(json.dumps({"passed": report["passed"], "receipt": str(out / "result.json")}), flush=True)
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
