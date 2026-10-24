#!/usr/bin/env python3
"""Inventory pinned native external obligations without rebuilding or executing tools.

ELF imports, copy relocations and object relocations are evidence, not a proof
of all possible runtime loading. Source declarations are advisory signatures;
only separately reviewed contracts may drive wrapper generation.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import subprocess
from catalog_scenario_obligations import build_inventory, markdown as scenario_markdown, aggregate_completeness
from catalog_adapter_generation import audit as audit_generation

PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"
TOOLS = ("ssh sshd sshd-session sshd-auth ssh-add ssh-keygen ssh-keyscan "
         "ssh-keysign ssh-pkcs11-helper ssh-agent scp sftp-server sftp ssh-sk-helper").split()
GROUPS = {
 "native-startup": "_ITM_deregisterTMCloneTable _ITM_registerTMCloneTable __cxa_finalize __gmon_start__ __libc_start_main __stack_chk_fail",
 "runtime-globals": "environ __environ __progname program_invocation_short_name program_invocation_name stdin stdout stderr optarg optind optopt opterr",
 "identity-and-accounts": "getuid geteuid getgid getegid getgrgid getgrnam getgrouplist getgroups getpwent getpwnam getpwuid getspnam endgrent endpwent setpwent initgroups innetgr setegid seteuid setgid setgroups setresgid setresuid setuid login logout logwtmp",
 "process-and-signals": "_exit abort exit alarm daemon execl execlp execv execve execvp fork getpgid getpgrp getpid getppid getsid kill killpg nanosleep pipe prctl raise setitimer setsid sigaction sigaddset sigemptyset sigfillset sigprocmask sleep system usleep waitpid",
 "network-and-resolver": "accept bind connect freeaddrinfo freeifaddrs gai_strerror getaddrinfo gethostname getifaddrs getnameinfo getpeername getservbyname getsockname getsockopt inet_ntop listen poll ppoll recvmsg sendmsg setsockopt shutdown socket socketpair __h_errno_location __res_init __res_state dn_expand res_query",
 "files-descriptors-and-paths": "access chdir chmod chown chroot close close_range closedir dirfd dirname dup dup2 fchmod fchmodat fchown fchownat fcntl fdopen fstat fstatat fstatvfs fsync ftruncate futimes getcwd ioctl link lseek lstat madvise mkdir mkdirat mkdtemp mkstemp mmap munmap open openat opendir read readdir readlink readv rename rewind rmdir stat statvfs symlink truncate umask unlink unlinkat utimensat utimes write writev __read_chk __realpath_chk __xpg_basename",
 "terminal": "cfgetispeed cfgetospeed cfsetispeed cfsetospeed isatty openpty tcgetattr tcgetpgrp tcsendbreak tcsetattr ttyname",
 "time-locale-and-environment": "__ctype_get_mb_cur_max clock_gettime ctime getenv getpagesize getrlimit gettimeofday localtime localtime_r mbtowc mktime nl_langinfo setenv setlocale setrlimit strftime strptime sysconf time timegm uname unsetenv wcwidth",
 "stdio-format-and-logging": "__asprintf_chk __fprintf_chk __getdelim __isoc23_fscanf __isoc23_sscanf __printf_chk __snprintf_chk __syslog_chk __vasprintf_chk __vfprintf_chk __vsnprintf_chk closelog fclose feof ferror fflush fgetc fgets fileno fopen fputc fputs fseek fwrite openlog pclose perror popen putchar puts snprintf setvbuf",
 "memory-and-strings": "__ctype_b_loc __ctype_tolower_loc __ctype_toupper_loc __errno_location __explicit_bzero_chk __isoc23_strtol __isoc23_strtoll __isoc23_strtoull __memcpy_chk __memmove_chk __memset_chk calloc fnmatch free isalnum isalpha isblank iscntrl isdigit isgraph islower isprint ispunct isspace isupper isxdigit malloc memchr memcmp memcpy memmem memmove memset qsort realloc reallocarray strcasecmp strcasestr strchr strcmp strcspn strdup strerror strlcat strlcpy strlen strncasecmp strncmp strncpy strndup strnlen strpbrk strrchr strsep strsignal strspn strstr strtod strtok",
 "entropy": "arc4random arc4random_buf arc4random_uniform",
 "dynamic-provider": "dlclose dlerror dlopen dlsym",
 "password-cryptography": "crypt",
}
CATEGORY = {s:g for g, names in GROUPS.items() for s in names.split()}
FS_NAMES = set("mkdir rmdir open close write lseek read pwrite pread umask rename link symlink readlink stat lstat truncate unlink chmod chown chdir opendir readdir rewinddir closedir printf vprintf vsnprintf".split())

def sha(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()

def command(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE)

def symbols(path, flags):
    result = {}
    for line in command(["nm", "--format=posix", *flags, str(path)]).splitlines():
        parts = line.split()
        if len(parts) > 1:
            result[parts[0].split("@")[0]] = parts[1]
    return result

def dynamic(path):
    rows = {}
    for line in command(["readelf", "--dyn-syms", "--wide", str(path)]).splitlines():
        p = line.split()
        if len(p) >= 8 and p[0].endswith(":") and p[6] == "UND":
            name = p[7].split("@")[0]
            rows[name] = {"kind":p[3], "binding":p[4], "versioned":p[7],
                          "evidence":"ELF undefined dynamic symbol"}
    for line in command(["readelf", "-rW", str(path)]).splitlines():
        p = line.split()
        if len(p) >= 5 and p[2].endswith("_COPY"):
            name = p[4].split("@")[0]
            rows[name] = {"kind":"OBJECT", "binding":"GLOBAL", "versioned":p[4],
                          "evidence":"ELF copy relocation"}
    needed = re.findall(r"Shared library: \[([^\]]+)\]",
                        command(["readelf", "-d", str(path)]))
    return rows, needed

def linked_compile_units(path, known):
    text=command(["readelf","--debug-dump=info","--dwarf-depth=1",str(path)])
    selected=set()
    unknown=[]
    for unit in text.split("Compilation Unit @")[1:]:
        name=re.search(r"DW_AT_name\s*:\s*(?:\([^\n]*?\):\s*)?([^\n]+)",unit)
        directory=re.search(r"DW_AT_comp_dir\s*:\s*(?:\([^\n]*?\):\s*)?([^\n]+)",unit)
        if name is None or directory is None:
            continue
        full=str(Path(directory.group(1).strip())/name.group(1).strip())
        relative=full.split("/reference-source/",1)[-1]
        if relative in known:
            selected.add(relative)
        else:
            unknown.append(full)
    if not selected:
        raise ValueError("No pinned source compilation units in native debug information: "+str(path))
    return sorted(selected),unknown,hashlib.sha256(text.encode()).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--contracts", type=Path)
    ap.add_argument("--adapter-check", type=Path)
    ap.add_argument("--native-trace", type=Path, help="Existing native trace manifest; no scenarios launched")
    ap.add_argument("--generation-only", type=Path, help="Replay all generation routes from an existing pinned catalog; no native census/build/test")
    ap.add_argument("--generation-stage", action="append", default=[], metavar="LABEL=FAMILY_DIR",
                    help="Separate staged family overlay; canonical report is always retained")
    ap.add_argument("--proof-evidence", type=Path, help="Retain a proposed certificate as pending actual checker verification")
    ap.add_argument("--require-generation-complete", action="store_true",
                    help="Exit nonzero after writing evidence if any semantic/execution obligation remains")
    a = ap.parse_args()
    root = a.workspace.resolve(strict=True)
    if a.generation_only:
        record = json.loads(a.generation_only.read_text())
        report = audit_generation(root, record, a.output, a.generation_stage, a.proof_evidence)
        print(json.dumps({p["profile"]:p["counts"] for p in report["profiles"]},sort_keys=True))
        if a.require_generation_complete and report["completeness"]["claim"] is not True:
            raise SystemExit(1)
        return
    if a.generation_stage or a.proof_evidence or a.require_generation_complete:
        ap.error("generation options require --generation-only")
    src, fork = root/"work/reference-source", root/"work/cerberus-lean"
    census_path = root/"outputs/openssh-lean/evidence/c-source-census.json"
    census = json.loads(census_path.read_text())
    if census["openssh_commit"] != PIN:
        raise ValueError("Wrong pinned OpenSSH census")
    configured=(src/"config.h").read_text()
    if re.search(r"(?m)^#define\s+(WITH_OPENSSL|WITH_ZLIB)\b",configured):
        raise ValueError("This catalog profile excludes OpenSSL and zlib; regenerate the profile deliberately")
    identities = {"config.h":sha(src/"config.h"), "Makefile":sha(src/"Makefile"),
                  "census":sha(census_path), "generator":sha(__file__)}
    objects, advisory, definitions = {}, defaultdict(list), defaultdict(list)
    for unit in census["translation_units"]:
        # Census historical path prefix is retired; source relative path is
        # verified against the pinned hash in the authoritative WSL checkout.
        source = src/unit["source"]
        if sha(source) != unit["source_sha256"]:
            raise ValueError("Pinned source mismatch: "+str(source))
        obj = source.with_suffix(".o")
        if obj.is_file():
            objects[unit["source"]] = {
                "path":str(obj), "sha256":sha(obj),
                "defined":symbols(obj, ["-g", "--defined-only"]),
                "undefined":symbols(obj, ["--undefined-only"])}
        survey = unit.get("advisory_clang_source_survey", {})
        for name, count in survey.get("call_sites_by_direct_callee", {}).items():
            advisory[name].append({"source":unit["source"], "count":count})
        for row in survey.get("function_definitions_including_headers", []):
            definitions[row["name"]].append({"source":unit["source"], "type":row["type"]})
    tools, imports = {}, defaultdict(list)
    for tool in TOOLS:
        exe = src/tool
        dyn, needed = dynamic(exe)
        # Native debug compilation units identify actual linked sources.
        # Matching only global symbol names would incorrectly put every
        # tool's distinct "main" object into every executable.
        contributing,external_units,dwarf_sha=linked_compile_units(exe,objects)
        tools[tool] = {"path":str(exe), "sha256":sha(exe), "needed":needed,
                      "undefined_dynamic_count":sum(x["evidence"].startswith("ELF undefined") for x in dyn.values()),
                      "external_symbol_count":len(dyn), "linked_source_units":contributing,
                      "linked_unit_evidence":"ELF DWARF compile-unit name and directory, matched to pinned source hashes",
                      "dwarf_compile_units_sha256":dwarf_sha,"external_compile_units":external_units}
        for name, entry in dyn.items():
            imports[name].append({"tool":tool, **entry})
    libc = defaultdict(list)
    core_proxies = defaultdict(list)
    core_path=fork/"runtime/libcore/std.core"
    core_text=core_path.read_text()
    identities["core_stdlib"]=sha(core_path)
    for m in re.finditer(r'ailname\s*=\s*"([^"]+)"',core_text):
        core_proxies[m.group(1)].append({"path":str(core_path.relative_to(root)),"line":core_text.count("\n",0,m.start())+1})
    # This detects a body, not just a header prototype. It does not certify that
    # the body implements every case or that its Core dependencies are present.
    function = re.compile(r"(?m)^[A-Za-z_][A-Za-z_0-9 \t*\n]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")
    for path in sorted((fork/"runtime/libc/src").glob("*.c")):
        text = path.read_text()
        identities[str(path.relative_to(root))]=sha(path)
        for m in function.finditer(text):
            libc[m.group(1)].append({"path":str(path.relative_to(root)),
                                   "line":text[:m.start()].count("\n")+1})
    decls = defaultdict(dict)
    # Source signatures are extracted only for established linker obligations.
    # No unused header declaration becomes a catalog obligation.
    for unit in census["translation_units"]:
        pp = unit["preprocessing"]
        path = Path(pp["path"])
        if not path.is_file() or sha(path) != pp["sha256"]:
            raise ValueError("Pinned preprocessing mismatch: "+str(path))
        clean = re.sub(r"(?m)^#.*$", "", path.read_text(errors="strict"))
        for m in re.finditer(r"\bextern\s+[^;{}]+;", clean):
            declaration = " ".join(m.group().split())
            names = set(re.findall(r"\b([A-Za-z_]\w*)\s*\(", declaration))
            names |= set(re.findall(r'__asm__\s*\(\s*"([^"]+)"\s*\)', declaration))
            for name in names & imports.keys():
                decls[name].setdefault(declaration, {
                    "text":declaration, "preprocessed_source":unit["source"],
                    "preprocessed_sha256":pp["sha256"],
                    "status":"extracted declaration; not a validated native ABI contract"})
    contracts = {}
    if a.contracts:
        contracts = {x["symbol"]:x for x in json.loads(a.contracts.read_text())["apis"]}
        identities["contracts"] = sha(a.contracts)
    verified_contracts=set()
    adapter_check=None
    if a.adapter_check:
        check=json.loads(a.adapter_check.read_text())
        if check.get("passed") is not True or check.get("inputs_unchanged") is not True:
            raise ValueError("Adapter check is not a complete pass")
        for name,want in check["source_hashes"].items():
            if sha(name)!=want:
                raise ValueError("Adapter check inputs have changed: "+name)
        known_test_symbols={"write","getuid","geteuid","getgid","getegid"}
        verified_contracts=set(contracts) & known_test_symbols
        adapter_check={"path":str(a.adapter_check.resolve()),"sha256":sha(a.adapter_check),
                       "scope":check["scope"],"covered_apis":sorted(verified_contracts)}
    known_gaps = {
        "time":{"path":"work/cerberus-lean/runtime/libc/src/time.c","line":7,
                "observation":"returns constant zero and does not store through timer; source has TODO"},
        "clock_gettime":{"path":"work/cerberus-lean/runtime/libc/src/time.c","line":14,
                "observation":"TODO body stores zero seconds/nanoseconds and returns success"},
        "isatty":{"path":"work/cerberus-lean/runtime/libc/src/unistd.c","line":11,
                "observation":"TODO body returns zero for every descriptor"},
        "utimensat":{"path":"work/cerberus-lean/runtime/libc/src/stat.c","line":49,
                "observation":"intended syscall body is commented TODO; executable body returns success without updating timestamps"},
    }
    rows = []
    for name, uses in sorted(imports.items()):
        callers = []
        for source,o in objects.items():
            if name in o["undefined"]:
                matching = [t for t in tools if source in tools[t]["linked_source_units"] and any(u["tool"]==t for u in uses)]
                if matching:
                    callers.append({"source":source, "tools":matching,
                                    "evidence":"undefined object relocation and linked DWARF compilation unit"})
        category = CATEGORY.get(name, "needs-classification")
        contract = contracts.get(name)
        model = libc.get(name, [])
        proxies = core_proxies.get(name, [])
        status = ("generated-adapter-tested-host-dispatch-pending" if name in verified_contracts else
                  "generated-contract-awaits-integration-and-validation" if contract else
                  "native-loader/compiler-obligation" if category=="native-startup" else
                  "modeled-global-or-object-layout-required" if category=="runtime-globals" else
                  "existing-placeholder-is-a-semantic-gap" if name in known_gaps else
                  "core-proxy-present-host-filesystem-effect-missing" if name in FS_NAMES else
                  "existing-core-proxy-awaits-compatibility-validation" if proxies else
                  "existing-model-body-awaits-compatibility-validation" if model else
                  "missing-reviewed-contract-and-host-dispatch")
        rows.append({
            "symbol":name, "service":category, "tools":sorted(u["tool"] for u in uses),
            "native_evidence":uses, "callers":callers,
            "advisory_source_calls":advisory.get(name, []),
            "signature_candidates":list(decls[name].values()),
            "existing_model_bodies":model,
            "existing_core_proxies":proxies,
            "known_model_gap":known_gaps.get(name),
            "interface_kind":"data" if any(x["kind"]=="OBJECT" for x in uses) else "callable" if any(x["kind"]=="FUNC" for x in uses) else "linker-symbol",
            "existing_fs_operation":name in FS_NAMES,
            "host_dispatch":"not integrated; pure CerbFS refuses filesystem effects",
            "contract":contract,
            "status":status,
            "priority":0 if contract else 1 if any(u["tool"]=="ssh" for u in uses) and category!="native-startup" else 2,
            "tests":{"native_symbol_observation":True,"generated_adapter_execution":name in verified_contracts,
                     "cerberus_host_execution":False,"behavioral_equivalence":False},
            "boundary":("native loader/compiler machinery; not automatically an interpreted C API" if category=="native-startup" else
                        "Cerberus objects and provenance must be marshalled under a reviewed contract; explicit IO result/errno and modeled writeback, no raw pointer cast"),
            "observations":{"api_entry_observed":False,"syscall_observation_is_not_api_coverage":True},
            "dynamic_indirect_transitive_coverage":"not established by ELF symbol enumeration",
        })
    unresolved_obj = set().union(*(set(o["undefined"]) for o in objects.values()))
    program_definitions = set().union(*(set(o["defined"]) for o in objects.values()))
    additional = []
    for name in sorted(unresolved_obj - program_definitions - imports.keys()):
        sources=[s for s,o in objects.items() if name in o["undefined"]]
        caller_tools=sorted({t for s in sources for t in tools if s in tools[t]["linked_source_units"]})
        compiler_helper=name=="_GLOBAL_OFFSET_TABLE_" or re.fullmatch(r"__(?:add|mul|neg|sub)v(?:di|si)[23]",name) is not None
        additional.append({"symbol":name,"sources":sources,"candidate_tools":caller_tools,
            "category":"native-compiler-helper" if compiler_helper else "object-only-library-candidate",
            "disposition":"C semantics covers arithmetic; native compiler helper is not automatically a modeled external C call" if compiler_helper else
                          "not present in final dynamic imports; compatibility member may be unlinked, requires link-map/source confirmation",
            "status":"not-counted-as-required-dynamic-adapter","implementation_verified":False})
    record = {
        "schema":1,"scope":"Pinned configured portable OpenSSH on native x86_64 Linux; adapter obligations, not completed support",
        "openssh_commit":PIN,"configuration":{"without_openssl":True,"without_zlib":True},
        "identities":identities,"tools":tools,"symbols":rows,"adapter_check":adapter_check,
        "counts":{"tools":len(tools),"symbols_including_copy_relocations":len(rows),
                  "ssh_symbols_including_copy_relocations":tools["ssh"]["external_symbol_count"],
                  "by_service":dict(Counter(r["service"] for r in rows)),
                  "callable_dynamic_symbols":sum(r["interface_kind"]=="callable" for r in rows),
                  "data_dynamic_symbols":sum(r["interface_kind"]=="data" for r in rows),
                  "linker_symbols":sum(r["interface_kind"]=="linker-symbol" for r in rows),
                  "existing_model_body_candidates":sum(bool(r["existing_model_bodies"]) for r in rows),
                  "existing_core_proxy_candidates":sum(bool(r["existing_core_proxies"]) for r in rows),
                  "identified_existing_placeholder_gaps":sum(r["known_model_gap"] is not None for r in rows),
                  "symbols_with_signature_candidates":sum(bool(r["signature_candidates"]) for r in rows),
                  "annotated_generation_contracts":len(contracts),"tested_generated_adapters":len(verified_contracts),"integrated_host_adapters":0},
        "additional_object_undefined_candidates":additional,
        "abi_and_state_gaps":[
            "Host Linux errno numbers differ from Builtins.translate_errno abstract enumeration; response carries native number and symbolic name, dispatcher must choose source ABI explicitly.",
            "Guest FILE, passwd, stat, dirent, sockaddr and other structured objects require declared field/layout/ownership marshalling; native addresses cannot be cast into Cerberus pointers.",
            "Native environment/process credentials/descriptors/signals must correspond to modeled process state. Fork/exec/callbacks require explicit scheduler and memory-state contracts.",
            "Native stdio formatting can bypass Cerberus varargs/provenance; reuse validated modeled format decoding or generate full ABI adapters, not variadic raw forwarding.",
            "Pure driver eagerly consumes FS effects and captures stdout/stderr internally; an explicit yielding host dispatcher remains required.",
        ],
        "source_indirect_call_observations":advisory.get("<indirect>",[]),
        "limitations":[
          "Exhaustive over the dynamic-symbol and copy-relocation tables of these 14 exact ELF files only.",
          "Native optimization can remove or introduce calls. Object/static-source observations are included separately.",
          "Callers identify object relocations within linked DWARF compilation units, not path-sensitive function call reachability.",
          "Advisory Clang calls include inline header bodies and used a different preprocessing path; they are not the denominator.",
          "No trace establishes unobserved branches, callbacks, arbitrary dlsym/PKCS#11/FIDO providers, subprocess programs or transitive libc/NSS behavior.",
          "OpenSSL/zlib/PAM/Kerberos/SELinux and alternate platform/configuration APIs remain outside this configured inventory; full pinned-release objective still includes applicable profiles.",
          "A libc source body is an implementation candidate, not an execution or equivalence pass.",
          "Generated wrapper contracts and syscall traces do not prove the host OS or native-library semantics in Lean.",
        ]}
    native_trace = {}
    if a.native_trace:
        native_trace = json.loads(a.native_trace.read_text())
        if native_trace.get("openssh_commit") != PIN or native_trace.get("schema") != 1:
            raise ValueError("Native receipt has unknown schema or pinned source")
        record["native_trace_inventory_input"] = {"path": str(a.native_trace.resolve()),
            "sha256": sha(a.native_trace), "native_execution_only": True}
    record["scenario_coverage"] = build_inventory(
        src, tools, native_trace.get("scenario_plan", []), native_trace.get("scenarios", []),
        configuration_hashes={name: identities[name] for name in ("Makefile", "config.h")})
    record["completeness"] = aggregate_completeness(
        ("source_and_scenarios", record["scenario_coverage"]),
        ("linked_core_obligations", record.get("linked_core_obligations")))
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    (out/"adapter-catalog.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    lines=["# Adapter catalog","","Pinned configuration: Linux x86-64, without OpenSSL and zlib.",
           "These are required interfaces or existing model candidates, not completed adapters.","",
           f"{len(rows)} distinct external symbols across {len(tools)} tools; {tools['ssh']['external_symbol_count']} for ssh, including copied data globals.","",
           f"{len(contracts)} annotated contracts; {len(verified_contracts)} generated adapters tested against the native oracle; 0 integrated interpreter host adapters.","",
           "| Service | All symbols | ssh symbols | Existing model body candidates |",
           "| --- | ---: | ---: | ---: |"]
    for group in sorted(set(r["service"] for r in rows)):
        subset=[r for r in rows if r["service"]==group]
        lines.append(f"| {group} | {len(subset)} | {sum('ssh' in r['tools'] for r in subset)} | {sum(bool(r['existing_model_bodies']) for r in subset)} |")
    lines += ["","## All symbols","","| Symbol | Service | Tools | Model / contract status |","| --- | --- | --- | --- |"]
    for row in rows:
        lines.append("| "+ " | ".join([row["symbol"],row["service"],", ".join(row["tools"]),row["status"]])+" |")
    lines += ["","## Known existing model gaps","","| Function | Source evidence |","| --- | --- |"]
    for name,gap in known_gaps.items():
        lines.append(f"| {name} | {gap['path']}:{gap['line']}: {gap['observation']} |")
    lines += ["","## Object-only candidates","","| Symbol | Classification | Candidate tools |","| --- | --- | --- |"]
    for row in additional:
        lines.append(f"| {row['symbol']} | {row['category']} | {', '.join(row['candidate_tools']) or 'none identified'} |")
    lines += ["","## ABI and state gaps",""]+["- "+x for x in record["abi_and_state_gaps"]]
    lines += ["","## Coverage limits",""]+["- "+x for x in record["limitations"]]
    lines += scenario_markdown(record["scenario_coverage"])
    (out/"adapter-catalog.md").write_text("\n".join(lines)+"\n")
    print(json.dumps(record["counts"],sort_keys=True))

if __name__=="__main__":
    main()
