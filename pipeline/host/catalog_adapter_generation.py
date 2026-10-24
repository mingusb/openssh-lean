"""Generation attempts for every known catalog obligation; no build or semantic proof.

Imported by catalog_host_adapters.py. Uses the existing maintained generators.
A missing contract is an attempted, blocked route, never a generated success stub.
"""
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

STAGES = ("contract", "abi_signature", "native_emission", "guest_memory",
          "exact_admission", "request_construction", "interpreter_dispatch",
          "execution_verification")
PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def names(document, fields=("apis",)):
    result = []
    for field in fields:
        for row in document.get(field, []):
            if not row.get("helper", False):
                result.append(row["symbol"])
    if len(result) != len(set(result)):
        raise ValueError("duplicate generation contract symbol")
    return set(result)


def source_inputs(base):
    return {str(p.resolve()): sha(p) for p in sorted(base.rglob("*"))
            if p.is_file() and "generated" not in p.relative_to(base).parts
            and "__pycache__" not in p.parts and p.suffix in {".py", ".json", ".in", ".lean", ".h", ".c"}}


def attempt_generator(identifier, script, arguments, out):
    """One shared emission attempt; its result is applied only to declared rows."""
    script = Path(script)
    inputs = {str(script): sha(script)} if script.is_file() else {}
    for item in arguments.values():
        item = Path(item)
        if item.is_file():
            inputs[str(item)] = sha(item)
    record = {"id": identifier, "inputs": inputs, "status": "blocked",
              "output_hashes": {}, "checks": []}
    if not script.is_file():
        record["gap"] = "generator_missing"
        return record
    argv = [sys.executable, str(script)]
    for flag, value in arguments.items():
        argv.extend([flag, str(value)])
    argv.extend(["--output", str(out)])
    out.mkdir(parents=True, exist_ok=True)
    for check in (False, True):
        completed = subprocess.run(argv + (["--check"] if check else []),
                                   capture_output=True, text=True)
        # Do not publish output-directory-dependent prose as deterministic state.
        normalize = lambda text: text.replace(str(out), "$OUTPUT").strip()
        record["checks"].append({"freshness": check, "exit_code": completed.returncode,
            "stdout": normalize(completed.stdout), "stderr": normalize(completed.stderr)})
        if completed.returncode:
            record["gap"] = "generator_failed" if not check else "freshness_failed"
            return record
    record["output_hashes"] = {str(p.relative_to(out)): sha(p)
                              for p in sorted(out.rglob("*")) if p.is_file()}
    if not record["output_hashes"]:
        record["gap"] = "generator_emitted_nothing"
        return record
    if any(not Path(path).is_file() or sha(path) != digest for path, digest in inputs.items()):
        record["gap"] = "generation_inputs_changed"
        return record
    record["status"] = "emitted_and_fresh"
    record["gap"] = None
    return record


def family_provider(family, base, state, output, driver):
    """Map current maintained schemas. Unknown schemas remain explicit failures."""
    provider = {"family": family, "state": state, "root": str(base),
                "native": set(), "guest": set(), "admission": set(), "requests": set(),
                "dispatch": set(), "contracts": {}, "attempts": {}, "issues": [],
                "fixture_symbols": set(), "source_hashes": source_inputs(base)}
    specs = {
        "files": ("generate_host_files.py", "files-contracts.json"),
        "network": ("generate_network_adapters.py", "network-contracts.json"),
        "system": ("generate_system_adapters.py", "system-contracts.json"),
    }
    generator, contract_name = specs[family]
    try:
        contract = load(base / contract_name)
        provider["native"] = names(contract)
        provider["contracts"] = {a["symbol"]: a for a in contract["apis"] if not a.get("helper")}
        provider["attempts"]["native"] = attempt_generator(family + "-native", base/generator,
            {"--contracts": base/contract_name}, output/"native")
        plan = load(base/"family-plan.json")
        provider["fixture_symbols"] = set(plan.get("tested_symbols", []))
        if family in {"files", "network"}:
            guest_name = "files-guest-contracts.json" if family == "files" else "network-guest-contracts.json"
            guest_generator = "generate_files_guest.py" if family == "files" else "generate_network_guest.py"
            guest = load(base/"guest"/guest_name)
            provider["guest"] = names(guest)
            declared_hash = guest.get("native_contracts_sha256")
            if declared_hash and declared_hash != sha(base/contract_name):
                provider["issues"].append({"gap":"native_guest_contract_hash_conflict"})
                provider["guest"] = set()
            provider["attempts"]["guest"] = attempt_generator(family+"-guest",base/"guest"/guest_generator,
                {"--contracts":base/"guest"/guest_name},output/"guest")
        if family == "network":
            admission = load(base/"admission/admission-contracts.json")
            provider["admission"] = names(admission)
            provider["requests"] = provider["admission"]
            provider["attempts"]["admission"] = attempt_generator("network-admission",
                base/"admission/generate_network_admission.py",
                {"--contracts":base/"admission/admission-contracts.json"},output/"admission")
            provider["attempts"]["dispatch"] = attempt_generator("network-handler",
                base/"handler/generate_network_handler.py",
                {"--contracts":base/"handler/handler-contracts.json"},output/"handler")
            provider["dispatch"] = provider["guest"] & provider["admission"]
            for copy_name, actual in [("network-native.json",base/contract_name),
                                      ("network-guest.json",base/"guest"/guest_name)]:
                copied=base/"handler/source-contracts"/copy_name
                if copied.read_bytes()!=actual.read_bytes():
                    provider["issues"].append({"gap":"handler_contract_snapshot_conflict","snapshot":copy_name})
                    provider["dispatch"]=set()

            provider["driver_hook"] = ("CerbHostNetworkHandler.performRequest" in driver and
                                       "CerbHostNetworkHandler.select" in driver)
        elif family == "files":
            admission = load(base/"normal/files-admission-contracts.json")
            provider["admission"] = names(admission, ("apis", "unresolved"))
            requests = load(base/"normal/files-request-contracts.json")
            provider["requests"] = names(requests)
            provider["attempts"]["admission"] = attempt_generator("files-admission",
                base/"normal/generate_files_admission.py",
                {"--contracts":base/"normal/files-admission-contracts.json"},output/"admission")
            provider["attempts"]["requests"] = attempt_generator("files-requests",
                base/"normal/generate_files_requests.py",
                {"--source":base/"normal/files-admission-contracts.json",
                 "--requests":base/"normal/files-request-contracts.json"},output/"requests")
            provider["attempts"]["extras"] = attempt_generator("files-extras",
                base/"normal/generate_files_extras.py",
                {"--contracts":base/"normal/files-request-contracts.json"},output/"extras")
            provider["dispatch"] = provider["requests"] & provider["guest"] & provider["admission"]
            provider["driver_hook"] = "def performExternalFiles" in driver
        else:
            codec = contract.get("guest_codecs", {})
            provider["guest"] = set(codec.get("symbols", []))
            if codec:
                provider["attempts"]["guest"] = provider["attempts"]["native"]
            # No canonical source admission/handler exists in this family package.
            # Staged additions must be supplied explicitly rather than inferred.
            provider["driver_hook"] = False
    except (KeyError, ValueError, OSError, TypeError) as error:
        provider["issues"].append({"gap":"provider_schema_or_input_error",
                                   "error":type(error).__name__+": "+str(error)})
    check_emission_membership(provider, output)
    return provider


def check_emission_membership(provider, output):
    """Require contract membership AND successful emission AND emitted source anchors.

    These anchors detect omitted generated entries, not semantic correctness.
    Exact signatures still need the real declaration gate and checked execution.
    """
    provider["emission_membership"]={}
    family=provider["family"]
    for key, declared in [("native",provider["native"]),("guest",provider["guest"]),
                          ("admission",provider["admission"]),("requests",provider["requests"]),
                          ("dispatch",provider["dispatch"])]:
        source_key="admission" if key=="requests" and family=="network" else key
        directory=output/source_key
        if family=="system" and key=="guest":directory=output/"native"
        if key=="dispatch" and family=="files":
            continue  # maintained transaction is reported separately, never as generated
        attempt=provider["attempts"].get(source_key)
        if not attempt or attempt["status"]!="emitted_and_fresh":continue
        if key=="native":
            files=sorted(directory.glob("*.c"))
        elif key=="guest":
            files=sorted(directory.glob("*Guest.lean")) if family!="system" else sorted(directory.glob("*Memory.lean"))
        elif key=="dispatch":
            files=sorted((output/"handler").glob("*.lean"))
        else:
            files=sorted(directory.glob("*.lean"))
        combined="\n".join(path.read_text() for path in files)
        members=[]
        for name in sorted(declared):
            escaped=re.escape(name)
            if key=="native":
                prefix={"base":"cerb_host_","files":"cerb_host_files_","network":"cerb_net_","system":"cerb_system_"}[family]
                pattern=r"\b"+prefix+escaped+r"_raw\s*\([^;]*?\)\s*\{"
            elif key=="guest":
                pattern=r"(?m)^\s*\|\s*(?:«"+escaped+r"»|"+escaped+r")(?:\s|$)"
            elif key=="admission":
                pattern=r'\|\s*"'+escaped+r'"\s*=>\s*some'
            elif key=="requests":
                pattern=r'\|\s*"'+escaped+r'"\s*,'
            else:
                pattern=r'\|\s*"'+escaped+r'"\s*=>\s*\.supported'
            if re.search(pattern,combined):members.append(name)
        provider["emission_membership"][key]={"contract_members":sorted(declared),
            "emitted_members":members,"omitted_members":sorted(declared-set(members)),
            "source_hashes":{str(path.relative_to(output)):sha(path) for path in files},
            "evidence_kind":"successful current generator plus contract membership plus emitted source anchor; not a semantic proof"}


def base_provider(fork, output, driver):
    contract_path = fork/"lean_frontend/host/host-contracts.json"
    contract = load(contract_path)
    result = {"family":"base", "state":"canonical", "root":str(contract_path.parent),
              "native":names(contract), "guest":set(), "admission":set(), "requests":set(),
              "dispatch":set(), "contracts":{a["symbol"]:a for a in contract["apis"]},
              "attempts":{}, "issues":[], "fixture_symbols":set(),
              "source_hashes":{str(contract_path):sha(contract_path)},
              "driver_hook":False}
    result["attempts"]["native"] = attempt_generator("base-native",
        fork/"scripts/generate_host_adapters.py",{"--contracts":contract_path},output/"native")
    result["manual_route_candidate"] = ["write","getuid","geteuid","getgid","getegid"]
    # Source bodies alone are not a machine-validated all-stage generator contract.
    result["manual_route_source"] = str(fork/"lean_frontend/CerbHostDriver.lean")
    check_emission_membership(result, output)
    return result


def missing(stage, gap, detail):
    return {"status":"blocked", "gap":gap, "detail":detail}


def stage_attempt(provider, stage, key, covered, name):
    if name not in covered:
        return missing(stage, stage+"_contract_missing",
                       "No declared current generator route for this symbol.")
    attempt = provider["attempts"].get(key)
    if not attempt or attempt["status"] != "emitted_and_fresh":
        return missing(stage, (attempt or {}).get("gap","generator_missing"),
                       "Declared route did not complete emission and freshness.")
    membership_key={"native_emission":"native","guest_memory":"guest",
        "exact_admission":"admission","request_construction":"requests",
        "interpreter_dispatch":"dispatch"}[stage]
    membership=provider.get("emission_membership",{}).get(membership_key)
    if membership is not None and name not in membership["emitted_members"]:
        return missing(stage,"declared_symbol_not_emitted","Contract declared the symbol but generated source omitted its reviewed entry.")
    return {"status":"generated_requires_validation", "attempt":attempt["id"],
             "contract_member":name,"emission_evidence":None if membership is None else {
                "provider_membership":membership_key,"output_hashes":membership["source_hashes"],
                "evidence_kind":membership["evidence_kind"]},
            "semantic_domain":"Contract restrictions remain; generation is not execution."}


def route_attempt(provider, row):
    name = row["symbol"]
    contract = provider["contracts"][name]
    stages = {"contract":{"status":"maintained_contract_present",
                           "contract_shape":contract.get("shape",contract.get("primitive",contract.get("kind")))},
              "abi_signature":{"status":"native_contract_present_call_admission_separate",
                               "source_candidates":len(row.get("signature_candidates",[]))},
              "native_emission":stage_attempt(provider,"native_emission","native",provider["native"],name),
              "guest_memory":stage_attempt(provider,"guest_memory","guest",provider["guest"],name),
              "exact_admission":stage_attempt(provider,"exact_admission","admission",provider["admission"],name)}
    req_key = "requests" if provider["family"] == "files" else "admission"
    stages["request_construction"] = stage_attempt(provider,"request_construction",req_key,provider["requests"],name)
    if name in provider["dispatch"]:
        if provider["family"] == "network":
            dispatch = stage_attempt(provider,"interpreter_dispatch","dispatch",provider["dispatch"],name)
        elif provider["family"] == "files" and provider.get("driver_hook"):
            dispatch = {"status":"maintained_driver_route_present_requires_validation",
                        "source":"CerbHostDriver.performExternalFiles",
                        "generated_request":True,"handwritten_transaction":True}
        else:
            dispatch = missing("interpreter_dispatch","interpreter_dispatch_missing","No source hook.")
        dispatch["canonical_hook_present"] = bool(provider.get("driver_hook"))
        dispatch["source_state"] = provider["state"]
        stages["interpreter_dispatch"] = dispatch
    else:
        stages["interpreter_dispatch"] = missing("interpreter_dispatch",
            "interpreter_dispatch_contract_missing","No complete declared request/handler composition.")
    stages["execution_verification"] = missing("execution_verification",
        "matching_execution_receipt_missing","No current bound native+guest+normal-call receipt supplied.")
    return {"family":provider["family"],"source_state":provider["state"],
            "stages":stages,"contract":contract,
            "fixture_declared_not_executed":name in provider["fixture_symbols"],
            "manual_route_candidate":name in provider.get("manual_route_candidate",[]),
            "provider_issues":provider["issues"],"complete":False}


def dynamic_literals(root, catalog):
    census_path = root/"outputs/openssh-lean/evidence/c-source-census.json"
    census = load(census_path)
    if census.get("openssh_commit") != PIN:
        raise ValueError("dynamic source scan has wrong pinned source")
    literals = defaultdict(list)
    identities = {str(census_path):sha(census_path)}
    for unit in census["translation_units"]:
        pp = unit["preprocessing"]
        path = Path(pp["path"])
        if not path.is_file() or sha(path) != pp["sha256"]:
            raise ValueError("dynamic source scan preprocessing changed: "+str(path))
        identities[str(path)] = pp["sha256"]
        text = path.read_text()
        for match in re.finditer(r'\bdlsym\s*\(\s*[^,;{}]+\s*,\s*"([^"\\]+)"\s*\)', text):
            literals[match.group(1)].append({"source":unit["source"],
                "preprocessed_sha256":pp["sha256"],"preprocessed_line":text.count("\n",0,match.start())+1})
    rows = []
    for symbol, sites in sorted(literals.items()):
        tools = sorted({tool for tool,info in catalog["tools"].items()
                        if any(site["source"] in info["linked_source_units"] for site in sites)})
        rows.append({"id":"dynamic:"+symbol,"symbol":symbol,"scope":"dynamic_literal",
            "interface_kind":"dynamic-provider","service":"dynamic-provider","tools":tools,
            "sites":sites,"limitation":"Conservative exact-preprocessed literal observations, not all possible loader names or callback targets."})
    return rows, identities


def obligations(catalog, dynamic):
    rows = []
    for source in catalog["symbols"]:
        row = dict(source)
        row.update(id="catalog:"+source["symbol"],scope="elf_catalog")
        rows.append(row)
    for source in catalog.get("additional_object_undefined_candidates",[]):
        rows.append(dict(source,id="object:"+source["symbol"],scope="object_candidate",
            service="native-startup" if source["category"]=="native-compiler-helper" else "object-only",
            interface_kind="compiler-helper" if source["category"]=="native-compiler-helper" else "callable-candidate",
            tools=source.get("candidate_tools",[])))
    rows.extend(dynamic)
    for source in catalog.get("source_indirect_call_observations",[]):
        name=source["source"]
        tools=sorted(tool for tool,info in catalog["tools"].items() if name in info["linked_source_units"])
        rows.append({"id":"indirect:"+name,"symbol":"indirect calls in "+name,
            "scope":"source_indirect","interface_kind":"indirect-obligation","service":"indirect-targets",
            "tools":tools,"observation":source,
            "limitation":"Advisory Clang source survey is not actual linked Core target closure."})
    for key,detail in [
        ("linked-core","Actual linked program boundary/constructor extraction and model-effect closure"),
        ("dynamic-loader","Arbitrary provider names, function tables, callbacks and provider ABI/lifetime domains"),
        ("configuration","All applicable pinned-release configuration and platform profiles"),
        ("subprocess-service","Explicit external-program/service boundary and modeled process relation")]:
        rows.append({"id":"closure:"+key,"symbol":key,"scope":"closure",
            "interface_kind":"closure-obligation","service":key,
            "tools":list(catalog["tools"]),"obligation":detail})
    ids=[row["id"] for row in rows]
    if len(ids)!=len(set(ids)):
        raise ValueError("duplicate inventory obligation identity; refusing silent overwrite")
    return sorted(rows,key=lambda row:row["id"])


def blocked_route(row):
    kind=row["interface_kind"]
    if kind=="data":
        gap="data_layout_lifetime_binding_missing"
        detail="Data object requires an explicit guest object/lifetime/synchronization contract; a function stub is inapplicable."
    elif kind in {"linker-symbol","compiler-helper"}:
        gap="loader_compiler_boundary_disposition_unverified"
        detail="Resolve native machinery versus interpreted boundary explicitly; do not invent a callable adapter."
    elif kind in {"dynamic-provider","indirect-obligation","closure-obligation"}:
        gap={"dynamic-provider":"provider_abi_callback_contract_missing",
             "indirect-obligation":"indirect_target_closure_missing",
             "closure-obligation":"boundary_scope_closure_missing"}[kind]
        detail=row.get("obligation",row.get("limitation","Dynamic typed targets remain unresolved."))
    else:
        gap="reviewed_contract_missing"
        detail="No maintained contract drives any current native emission route; source signatures alone do not supply semantics."
    return {"family":None,"source_state":"none",
            "stages":{stage:missing(stage,gap if stage=="contract" else
                                   "prerequisite_"+gap,detail) for stage in STAGES},
            "model_candidate":bool(row.get("existing_model_bodies") or row.get("existing_core_proxies")),
            "complete":False}


def rank_gaps(rows, first_only=False):
    groups={}
    for row in rows:
        # Alternative routes are independent. An emitted stage in any complete
        # provider path removes only this stage's generator gap, never verification.
        for stage in STAGES:
            attempts=[route["stages"][stage] for route in row["generation_routes"]]
            if any(item["status"]!="blocked" for item in attempts):
                continue
            gaps=sorted({item["gap"] for item in attempts})
            group=row["service"]
            for gap in gaps:
                key=(stage,gap,group)
                item=groups.setdefault(key,{"stage":stage,"gap":gap,"service":group,
                    "catalog_rows":[],"ssh_catalog_rows":[],"other_obligations":[],
                    "ssh_other_obligations":[]})
                target="catalog_rows" if row["scope"]=="elf_catalog" else "other_obligations"
                item[target].append(row["id"])
                if "ssh" in row["tools"]:item["ssh_"+target].append(row["id"])
            if first_only:break
    result=[]
    for item in groups.values():
        for key in ["catalog_rows","ssh_catalog_rows","other_obligations","ssh_other_obligations"]:
            item[key]=sorted(set(item[key]))
            item[key+"_count"]=len(item[key])
        result.append(item)
    order={stage:i for i,stage in enumerate(STAGES)}
    return sorted(result,key=lambda item:(-item["catalog_rows_count"],
        -item["ssh_catalog_rows_count"],order[item["stage"]],item["service"],item["gap"]))


def verify_catalog_snapshot(root, catalog):
    if catalog.get("schema")!=1 or catalog.get("openssh_commit")!=PIN:
        raise ValueError("wrong catalog schema or pinned source")
    required={}
    for name in ("Makefile","config.h"):
        required[root/"work/reference-source"/name]=catalog["identities"][name]
    required[root/"outputs/openssh-lean/evidence/c-source-census.json"]=catalog["identities"]["census"]
    for info in catalog["tools"].values():required[Path(info["path"])]=info["sha256"]
    for path,digest in required.items():
        if not path.is_file() or sha(path)!=digest:
            raise ValueError("catalog native/configuration identity mismatch: "+str(path))
    return {str(path):digest for path,digest in sorted(required.items())}


def proof_status(catalog, supplied=None):
    binding={"openssh_commit":catalog["openssh_commit"],
             "configuration_sha256":catalog["identities"]["config.h"],
             "linked_program_sha256":None,"target_profile_sha256":None}
    result={"binding":binding,
        "syntactic_occurrence_coverage":{"status":"absent","theorem":None,
            "artifact_sha256":None,"checker_receipt":None,
            "requirement":"total actual-Core extractor, independent occurrence relation, Lean-checked inclusion theorem, exact linked-program/profile binding"},
        "semantic_runtime_inclusion":{"status":"absent","theorem":None,
            "artifact_sha256":None,"checker_receipt":None,
            "requirement":"runtime event relation, model closure and dynamic loader/provider contracts"},
        "known_rows_accounted_is_not_a_proof":True}
    if supplied:
        # Preserve supplied certificates as untrusted evidence until the actual
        # proof checker contract is available. Never promote a claimed boolean.
        result["supplied_unchecked"]={"path":str(supplied.resolve()),"sha256":sha(supplied),
                                     "manifest":load(supplied)}
        result["syntactic_occurrence_coverage"]["status"]="supplied_pending_checker"
    return result


def audit(root, catalog, output, overlays=(), proof=None):
    root=Path(root).resolve(strict=True);output=Path(output).resolve()
    allowed=(root/"outputs",root/"work/agent-patches",Path(__file__).resolve().parents[2] / "local/runtime")
    if not any(output.is_relative_to(base) for base in allowed):
        raise ValueError("Generation audit output must be workspace evidence/staging, never maintained fork source.")
    output.mkdir(parents=True,exist_ok=True)
    native_identities=verify_catalog_snapshot(root,catalog)
    dynamic,source_identities=dynamic_literals(root,catalog)
    required=obligations(catalog,dynamic)
    fork=root/"work/cerberus-lean"
    driver_path=fork/"lean_frontend/CerbHostDriver.lean"
    driver_hash=sha(driver_path)
    driver=driver_path.read_text()
    base_roots={name:fork/"lean_frontend/host/families"/name for name in ("files","network","system")}
    profiles=[("canonical",base_roots,{name:"canonical" for name in base_roots})]
    for specification in overlays:
        label,sep,path=specification.partition("=")
        if not sep or not re.fullmatch(r"[A-Za-z0-9_-]+",label) or label=="canonical":
            raise ValueError("generation stage must be unique label=family-directory")
        directory=Path(path).resolve(strict=True)
        if not directory.is_relative_to(root/"work/agent-patches"):
            raise ValueError("staged generation source must be an explicit project patch directory")
        family=load(directory/"family-plan.json")["family"]
        if family not in base_roots:raise ValueError("unsupported staged family")
        profiles.append((label,{**base_roots,family:directory},
                         {**{name:"canonical" for name in base_roots},family:"staged"}))
    if len({name for name,_,_ in profiles})!=len(profiles):
        raise ValueError("duplicate generation profile label")
    reports=[]
    for label,roots,states in profiles:
        providers=[base_provider(fork,output/label/"base",driver)]
        providers.extend(family_provider(family,roots[family],states[family],
                         output/label/family,driver) for family in sorted(roots))
        entries=[]
        for obligation in required:
            row={key:obligation.get(key) for key in ("id","scope","symbol","interface_kind","service","tools")}
            row["generation_attempted"]=True
            row["generation_routes"]=[route_attempt(provider,obligation) for provider in providers
                if obligation["symbol"] in provider["native"] and
                obligation["interface_kind"] in {"callable","callable-candidate"}]
            if not row["generation_routes"]:row["generation_routes"]=[blocked_route(obligation)]
            row["source_signature_candidates"]=obligation.get("signature_candidates",[])
            row["existing_model_candidates"]={"bodies":obligation.get("existing_model_bodies",[]),
                "proxies":obligation.get("existing_core_proxies",[]),"not_validated":True}
            row["complete"]=False
            entries.append(row)
        expected={row["id"] for row in required};actual={row["id"] for row in entries}
        if actual!=expected or len(entries)!=len(expected):
            raise ValueError("known obligation coverage is not exact")
        details=[]
        for provider in providers:
            details.append({key:(sorted(value) if isinstance(value,set) else value)
                for key,value in provider.items() if key not in {"contracts"}})
        reports.append({"profile":label,"source_roots":{key:str(value) for key,value in roots.items()},
            "counts":{"known_catalog_rows":sum(row["scope"]=="elf_catalog" for row in entries),
                "catalog_kinds":dict(sorted(Counter(row["interface_kind"] for row in entries if row["scope"]=="elf_catalog").items())),
                "additional_obligation_scopes":dict(sorted(Counter(row["scope"] for row in entries if row["scope"]!="elf_catalog").items())),
                "native_emitted_catalog_rows":sum(row["scope"]=="elf_catalog" and any(
                    route["stages"]["native_emission"]["status"]!="blocked" for route in row["generation_routes"]) for row in entries),
                "guest_generated_catalog_rows":sum(row["scope"]=="elf_catalog" and any(
                    route["stages"]["guest_memory"]["status"]!="blocked" for route in row["generation_routes"]) for row in entries),
                "attempted_rows":len(entries),"complete_adapters_verified":0},
            "known_inventory_accounting":{"expected_ids":sorted(expected),"observed_ids":sorted(actual),"exact":True},
            "providers":details,"entries":entries,"ranked_shared_gaps":rank_gaps(entries,first_only=True),
            "ranked_all_stage_gaps":rank_gaps(entries),
            "completeness":{"claim":False,"reasons":["Execution and semantic-domain obligations remain.",
                "Known inventory coverage does not establish complete linked/runtime boundary coverage."]}})
    result={"schema":1,"scope":"Attempt all known catalog entries with existing maintained generators; no compilation/execution/proof",
        "inventory_input_sha256":hashlib.sha256(json.dumps(catalog,sort_keys=True).encode()).hexdigest(),
        "native_inventory_identities":native_identities,"source_scan_identities":source_identities,
        "driver_source":{"path":str(driver_path),"sha256":driver_hash},
        "audit_generator_sha256":sha(__file__),"profiles":reports,
        "dynamic_literal_obligations":dynamic,
        "linked_core_obligations":catalog.get("linked_core_obligations"),
        "proof_evidence":proof_status(catalog,proof),
        "completeness":{"claim":False,"reasons":["All known rows attempted is not behavioral equivalence or a complete boundary proof.",
            "Unclosed indirect, dynamic, configuration, data/model and execution domains remain."]}}
    # Prevent concurrent changes from turning stale generation into new evidence.
    whole_run_inputs={**native_identities,**source_identities,str(driver_path):driver_hash}
    for report in reports:
        for provider in report["providers"]:
            for evidence in [provider["source_hashes"]]+[a["inputs"] for a in provider["attempts"].values()]:
                for path,digest in evidence.items():
                    if path in whole_run_inputs and whole_run_inputs[path]!=digest:
                        raise ValueError("source identity conflict between generation attempts: "+path)
                    whole_run_inputs[path]=digest
    for path,digest in whole_run_inputs.items():
        if not Path(path).is_file() or sha(path)!=digest:
            raise ValueError("maintained generator input changed during audit: "+path)
    result["inputs_unchanged"]=True
    (output/"adapter-generation.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    (output/"adapter-generation.md").write_text(markdown(result))
    return result


def markdown(report):
    lines=["# All-entry adapter generation attempts","",
        "Generated code, executed behavior and proof evidence are separate. No complete-adapter claim is made.",""]
    for profile in report["profiles"]:
        counts=profile["counts"]
        lines += ["## "+profile["profile"],"",
            f"All {counts['known_catalog_rows']} known ELF catalog rows attempted; "+
            f"{counts['native_emitted_catalog_rows']} have emitted native transport source and "+
            f"{counts['guest_generated_catalog_rows']} have emitted guest codec source.",
            "Additional object/provider/indirect/closure obligations remain separate from API counts.","",
            "| Stage | Shared gap | Service | Catalog | ssh | Other obligations |",
            "| --- | --- | --- | ---: | ---: | ---: |"]
        for gap in profile["ranked_shared_gaps"]:
            lines.append(f"| {gap['stage']} | {gap['gap']} | {gap['service']} | {gap['catalog_rows_count']} | {gap['ssh_catalog_rows_count']} | {gap['other_obligations_count']} |")
        lines += ["","### Every known row","",
            "| ID | Kind | Native emission | Guest codec | Exact admission | Dispatch | Verification |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
        for row in profile["entries"]:
            def statuses(stage):
                return "; ".join(sorted({r["stages"][stage].get("gap",r["stages"][stage]["status"])
                    for r in row["generation_routes"]}))
            lines.append("| "+" | ".join([row["id"],row["interface_kind"]]+
                [statuses(s) for s in ("native_emission","guest_memory","exact_admission","interpreter_dispatch","execution_verification")])+" |")
        lines.append("")
    return "\n".join(lines)+"\n"
