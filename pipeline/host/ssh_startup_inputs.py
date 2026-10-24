"""Pinned input preparation for check_host_dispatch's real ssh startup attempt.

No subprocesses: the existing checker owns every process, lease and cap.
Cached signature-only Core dumps are deliberately not execution inputs.
"""
import hashlib
import json
from pathlib import Path
import re

PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"
LIBC_TUS = ("ctype", "stdio", "stdlib", "string", "time", "utime", "unistd",
            "stat", "uio", "internal", "vfscanf", "signal")
VERSION = b"OpenSSH_10.6p1, without OpenSSL\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def indexed(rows, key, label):
    result = {row[key]: row for row in rows}
    require(len(result) == len(rows), f"Duplicate {label}")
    return result


def safe_relative(name):
    path = Path(name)
    require(not path.is_absolute() and ".." not in path.parts, "Escaping relative input")
    return path


def ordered_sources(arguments, link_map, required):
    """Match direct objects then first archive-selection rows, not sorted names."""
    sources = [str(safe_relative(arg).with_suffix(".c")) for arg in arguments
               if arg.endswith(".o") and not arg.startswith("-")]
    for line in link_map.splitlines():
        if line == "Merging object attributes":
            break
        match = re.match(r"^(?:\./)?(libssh\.a|openbsd-compat//libopenbsd-compat\.a)\(([^()]+\.o)\)", line)
        if match:
            archive, member = match.groups()
            prefix = "openbsd-compat/" if "compat" in archive else ""
            sources.append(prefix + str(safe_relative(member).with_suffix(".c")))
    require(len(sources) == len(set(sources)), "Duplicate direct/archive linked TU")
    require(len(required) == 90 and len(set(required)) == 90 and set(sources) == set(required),
            "ssh link order does not cover exactly the declared 90 TUs")
    return sources


def cabs_arguments(parser, installed, cpp, preprocessed):
    return [str(parser), "--runtime=" + str(installed), "--cabs-json",
            "--cpp=/usr/bin/python3 " + str(Path(cpp).resolve()), str(preprocessed)]


def load_inputs(root, runtime, parser):
    root, runtime, parser = Path(root), Path(runtime), Path(parser)
    evidence = root / "outputs/openssh-lean/evidence"
    paths = {"census": runtime / "c-import/census.json",
             "imports": runtime / "import-fork/import-report.json",
             "dependencies": evidence / "ssh-dependencies.json",
             "catalog": evidence / "adapter-catalog.json",
             "inventory": evidence / "source-inventory.json",
             "link_map": runtime / "ssh-dependencies/ssh.map"}
    data = {key: json.loads(path.read_bytes()) for key, path in paths.items() if key != "link_map"}
    census, imports, deps, catalog, inventory = (data[key] for key in
                                               ("census", "imports", "dependencies", "catalog", "inventory"))
    require(all(item["openssh_commit"] == PIN for item in (census, imports, deps, catalog)) and
            inventory["upstream_commit"] == PIN, "OpenSSH pin differs")
    require(census["schema_version"] == imports["schema_version"] == inventory["schema_version"] == 1,
            "Unsupported input schema")
    require(imports["census_sha256"] == sha(paths["census"]) and
            census["inventory_sha256"] == sha(paths["inventory"]), "Census/import/inventory binding differs")
    require(deps["link_map_sha256"] == sha(paths["link_map"]), "Link map changed")
    reference = root / "work/reference-source"
    require(Path(census["source_root"]) == reference, "Census is not the authoritative Linux checkout")
    require(catalog["configuration"] == {"without_openssl": True, "without_zlib": True},
            "Native profile differs")
    files = {str(path): sha(path) for path in paths.values()}
    def bind(path, expected):
        require(path.is_file() and sha(path) == expected, f"Pinned input changed: {path}")
        files[str(path)] = expected
    for name, key in (("config.h", "configuration_sha256"), ("Makefile", "makefile_sha256"),
                      ("config.status", "config_status_sha256")):
        bind(reference / name, census[key])
        if name in catalog["identities"]:
            require(catalog["identities"][name] == census[key], f"Native catalog {name} differs")
    for row in inventory["files"]:
        if Path(row["path"]).suffix in (".c", ".h"):
            bind(reference / safe_relative(row["path"]), row["sha256"])
    native = reference / "ssh"
    require(Path(catalog["tools"]["ssh"]["path"]) == native and
            catalog["tools"]["ssh"]["sha256"] == deps["native_reference_sha256"], "Native identity differs")
    bind(native, deps["native_reference_sha256"])
    dep_units = indexed(deps["units"], "source", "dependency TU")
    required = catalog["tools"]["ssh"]["linked_source_units"]
    require(set(dep_units) == set(required), "ELF/source closure inventories disagree")
    order = ordered_sources(deps["link_arguments"], paths["link_map"].read_text(), required)
    census_units = indexed(census["translation_units"], "source", "census TU")
    cached = indexed(imports["units"], "source", "cached TU")
    cpp = root / "outputs/openssh-lean/scripts/preprocessed_input.py"
    files[str(cpp)] = sha(cpp)
    parser_hash = sha(parser)
    reusable_producer = (imports["parser_binary_sha256"] == parser_hash and
                         imports["cpp_adapter_sha256"] == files[str(cpp)])
    units = []
    for source in order:
        row, dependency = census_units[source], dep_units[source]
        require(Path(row["file"]) == reference / safe_relative(source) and
                row["source_sha256"] == dependency["source_sha256"], "Source closure binding differs")
        bind(reference / source, row["source_sha256"])
        bind((reference / source).with_suffix(".o"), dependency["object_sha256"])
        pre = row["preprocessing"]
        pre_path = Path(pre["path"])
        require(pre["exit_code"] == 0 and pre["sha256"] == dependency["preprocessed_sha256"] and
                pre_path.resolve().is_relative_to(runtime / "c-import/units"), "Preprocessed closure differs")
        bind(pre_path, pre["sha256"])
        unit = {"source": source, "source_sha256": row["source_sha256"],
                "preprocessed": str(pre_path), "preprocessed_sha256": pre["sha256"], "cached_cabs": None}
        prior = cached.get(source)
        if reusable_producer and prior is not None:
            record = prior["parser"]
            path = Path(record["stdout_path"])
            if (prior["source_sha256"] == row["source_sha256"] and
                prior["preprocessed_sha256"] == pre["sha256"] and
                record["exit_code"] == 0 and not record.get("timed_out", False) and
                record["arguments"] == cabs_arguments(parser, runtime / "cerberus-lean/_build/install/default", cpp, pre_path) and
                path.resolve().is_relative_to(runtime / "import-fork/units") and
                path.is_file() and sha(path) == record["stdout_sha256"]):
                unit["cached_cabs"] = str(path)
                bind(path, record["stdout_sha256"])
        units.append(unit)
    return {"schema": 1, "openssh_commit": PIN, "source_root": str(reference),
            "input_files": files, "units": units, "native": str(native),
            "parser_sha256": parser_hash, "cached_parser_sha256": imports["parser_binary_sha256"],
            "cpp_adapter": str(cpp), "libc_precedes_program": True,
            "signature_only_core_used": False, "expected_exit": 0,
            "expected_stdout_hex": "", "expected_stderr_hex": VERSION.hex()}


def profile_is_current(folder, repo, preparer):
    """A cache hit is bound to current producer, runtime inputs and every artifact."""
    folder, repo, preparer = Path(folder), Path(repo), Path(preparer)
    try:
        profile = json.loads((folder / "profile.json").read_bytes())
        before = profile["before"]
        require(profile["profile"] == "gnu-amd64-physical-va-list" and
                profile["artifacts_prepared"] is True and profile["before"] == profile["after"] and
                profile["preparer_sha256"] == sha(preparer), "Unprepared/stale libc profile")
        require(before["compiler_sha256"] == sha(repo / "_build/default/backend/driver/main.exe") and
                before["lean_sha256"] == sha(repo / "lean_frontend/.lake/build/bin/cerberus-lean"),
                "Libc producer changed")
        prefix = [str(repo / "lean_frontend/.lake/build/bin/cerberus-lean"), "--runtime",
                  str(repo / "_build/install/default"), "--switches", "gnu_pointer_conversions",
                  "--libc", str(folder / "libc_gnu_amd64.core"),
                  *[arg for tu in LIBC_TUS for arg in ("--libc-tu", str(folder / f"libc_gnu_amd64_{tu}.json"))]]
        require(profile["commands"]["lean_prefix"] == prefix, "Libc selected flags/paths differ")
        require(not set(before["inputs"]).intersection(before["defaults"]), "Overlapping libc identities")
        required = {f"runtime/libc/src/{tu}.c" for tu in LIBC_TUS} | {"runtime/libcore/std.core", "runtime/dune"}
        require(required.issubset(before["inputs"]) and before["defaults"], "Incomplete libc input identity")
        for name, digest in {**before["inputs"], **before["defaults"]}.items():
            path = repo / safe_relative(name)
            require((sha(path) if path.exists() else None) == digest, f"Libc input changed: {name}")
        names = {"libc_gnu_amd64.co", "libc_gnu_amd64.core"} | {f"libc_gnu_amd64_{tu}.json" for tu in LIBC_TUS}
        require(set(profile["artifact_sha256"]) == names, "Libc artifact inventory changed")
        for name, digest in profile["artifact_sha256"].items():
            require(sha(folder / name) == digest, f"Libc artifact changed: {name}")
        require(len(profile["steps"]) == 14 and all(step.get("exit_code") == 0 and
                step.get("terminal") is True and step.get("timeout") is False for step in profile["steps"]),
                "Incomplete libc preparation")
        return True
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return False


def lean_arguments(interpreter, installed, folder, fuel, cabs):
    require(len(cabs) == 90 and len(set(map(str, cabs))) == 90, "Need exactly 90 distinct Cabs inputs")
    return [str(interpreter), "--pp-core", "--runtime", str(installed), "--switches", "gnu_pointer_conversions",
            "--libc", str(folder / "libc_gnu_amd64.core"),
            *[arg for tu in LIBC_TUS for arg in ("--libc-tu", str(folder / f"libc_gnu_amd64_{tu}.json"))],
            "--fuel", str(fuel), *map(str, cabs)]
