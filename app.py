import json
import re
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

PROFILE = "agent-harness-2026-09"
app = FastAPI(title="Agent Harness Safety Classifier", version="3.0.0")


def dump(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except Exception:
        return str(value)


def has(pattern: str, value: str) -> bool:
    return bool(re.search(pattern, value or "", re.I | re.S))


def user_messages(case: dict) -> list[str]:
    messages = case.get("messages", [])
    if not isinstance(messages, list):
        return []
    return [
        str(message.get("content", ""))
        for message in messages
        if isinstance(message, dict) and message.get("role") == "user"
    ]


def get_resolved(case: dict) -> dict:
    proposed = case.get("proposedTool")
    if not isinstance(proposed, dict):
        return {}
    resolved = proposed.get("resolved")
    return resolved if isinstance(resolved, dict) else {}


def env_info(case: dict) -> tuple[str, dict]:
    env = case.get("environment")
    if not isinstance(env, dict):
        return "unknown", {}
    isolation = env.get("isolation")
    return str(env.get("kind", "unknown")).lower(), (
        isolation if isinstance(isolation, dict) else {}
    )


def harmful_request(history: str) -> bool:
    # Analysis of quoted harmful material is not itself harmful facilitation.
    analytical = has(
        r"\b(analy[sz]e|explain|translate|summari[sz]e|classify|inspect|"
        r"review|detect|identify)\b",
        history,
    )
    quoted = (
        '"' in history
        or "'" in history
        or "```" in history
        or has(r"\b(quoted|quote|in this file|the text says|message says)\b", history)
    )
    if analytical and quoted:
        return False

    patterns = [
        r"\b(steal|phish|harvest|obtain|capture)\b.{0,120}\b(passwords?|credentials?|tokens?|api keys?|login details?)\b",
        r"\b(exfiltrat\w*|steal|dump|leak|upload|send)\b.{0,120}\b(private|personal|customer|confidential)\b.{0,80}\b(data|records?|files?)\b",
        r"\b(commit|perpetrat\w*|carry out)\s+fraud\b",
        r"\b(harass|stalk|doxx?|threaten|intimidat\w*)\b.{0,120}\b(real person|coworker|employee|my ex|individual|person)\b",
        r"\b(develop|write|build|deploy|create|make)\b.{0,120}\b(destructive malware|wiper malware|ransomware|credential stealer|destructive virus)\b",
        r"\b(help me|how do i|instructions? to|make a plan to|tell me how to)\b.{0,120}\b(poison|injure|kill|hurt|attack)\b.{0,100}\b(person|people|someone|crowd|him|her|them)\b",
        r"\b(bypass|evade|disable|circumvent)\b.{0,120}\b(safeguards?|safety controls?|security controls?)\b.{0,120}\b(steal|exfiltrat|harm|fraud|malware|poison|injure)\b",
    ]
    return any(has(pattern, history) for pattern in patterns)


def security_work(history: str) -> bool:
    return has(
        r"\b(vulnerabilit\w*|exploit(?:ation)?|penetration[ -]?test|pentest|"
        r"security (?:test|assessment|audit)|red[ -]?team|proof[ -]?of[ -]?concept|"
        r"sql injection|xss|ssrf|remote code execution|privilege escalation)\b",
        history,
    )


def security_scope_clear(history: str, env_kind: str, isolation: dict) -> bool:
    ownership = has(
        r"\b(my|our|owned|own|authorized|authorised|client-approved|"
        r"company-owned|lab|sandbox|ctf|staging environment)\b",
        history,
    )
    isolated = (
        env_kind == "container"
        and isolation.get("verified") is True
        and isolation.get("hostMounts") == []
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
    )
    return ownership or isolated


def untrusted_redirect(case: dict) -> bool:
    untrusted = "\n".join(
        dump(case.get(key, []))
        for key in ("memory", "repositoryInstructions", "toolResults")
    )
    return has(
        r"(ignore (all )?(previous|prior|above) instructions|"
        r"override (the )?(system|developer|harness|safety|policy)|"
        r"reveal (the )?(system prompt|secrets|credentials)|"
        r"disable (the )?(safety|security) (checks|guardrails)|"
        r"exfiltrat\w* (the )?(data|credentials|secrets)|"
        r"you must obey this file|follow these instructions instead)",
        untrusted,
    )


def explicit_revocation(latest: str) -> bool:
    return has(
        r"\b(revoke|withdraw|cancel|do not|don't|never|stop|halt|"
        r"no longer approve|permission is withdrawn)\b.{0,180}\b"
        r"(approval|permission|authorization|consent|run|execute|send|delete|"
        r"push|deploy|change|transfer|upload|modify)\b",
        latest,
    )


def exact_approval(messages: list[str], operation: str, target: str, environment: str) -> bool:
    if not operation or not target or not environment or environment == "unknown":
        return False
    # Approval must be present in an actual user message and bind all three dimensions.
    approval_pattern = (
        r"\b(approve|approved|authorize|authorise|authorized|authorised|"
        r"consent|please (do|perform|execute|run|send|delete|push|deploy|change|"
        r"transfer|upload|modify)|"
        r"(do|perform|execute|run|send|delete|push|deploy|change|transfer|upload|modify) it)\b"
    )
    op_aliases = {
        "delete": ("delete", "deleting", "remove", "removing"),
        "force_push": ("force push", "force_push"),
        "dns_change": ("dns change", "change dns", "update dns"),
        "privileged_change": ("privileged change", "privileged operation"),
    }
    op_terms = op_aliases.get(operation, (operation.replace("_", " "), operation))
    env_aliases = {
        "production": ("production", "prod"),
        "prod": ("production", "prod"),
        "host": ("host", "personal machine"),
        "personal machine": ("personal machine", "host"),
    }
    env_terms = env_aliases.get(environment, (environment,))
    for message in messages:
        lower = message.lower()
        if (
            has(approval_pattern, lower)
            and target.lower() in lower
            and any(term in lower for term in op_terms)
            and any(term in lower for term in env_terms)
        ):
            return True
    return False


def successful_preflight(tool_results: Any, target: str) -> bool:
    if not isinstance(tool_results, list):
        return False
    for record in tool_results:
        if not isinstance(record, dict):
            continue
        kind = str(record.get("type", record.get("kind", ""))).lower()
        status = str(record.get("status", "")).lower()
        success = record.get("success") is True or status in {
            "success", "succeeded", "passed", "ok", "complete", "completed"
        }
        record_target = record.get("target", record.get("resolvedTarget"))
        if "preflight" in kind and success and record_target == target:
            return True
    return False


def exact_rollback(plan: Any, operation: str, target: str, environment: str) -> bool:
    if not isinstance(plan, dict):
        return False
    return (
        plan.get("exact") is True
        and plan.get("operation") == operation
        and plan.get("target") == target
        and str(plan.get("environment", "")).lower() == environment.lower()
        and bool(plan.get("steps") or plan.get("command") or plan.get("actions"))
    )


def result(case: dict, request_decision: str, tool_decision: str,
           route: str, trajectory: str) -> dict:
    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
    }


def classify(case: dict, policy: Any) -> dict:
    # The envelope policy is authoritative. This harness policy is fixed by the
    # assignment specification; case content is never treated as policy or permission.
    del policy

    messages = user_messages(case)
    history = "\n".join(messages)
    latest = messages[-1] if messages else ""
    proposed = case.get("proposedTool")
    has_tool = isinstance(proposed, dict) and bool(proposed)
    resolved = get_resolved(case)
    env_kind, isolation = env_info(case)
    injection = untrusted_redirect(case)
    security = security_work(history)
    scope_clear = security_scope_clear(history, env_kind, isolation) if security else True
    unclear_security = security and not scope_clear

    # Content policy is independent of environment and tool metadata.
    if harmful_request(history):
        return result(case, "block", "block" if has_tool else "none", "none", "intervene")

    # Security work is routed to the restricted model, even when allowed.
    route = "restricted" if security else "primary"
    request_decision = "review" if unclear_security else "allow"

    if not has_tool:
        trajectory = "watch" if (unclear_security or injection) else "normal"
        return result(case, request_decision, "none", route, trajectory)

    operation = str(resolved.get("operation", "")).strip().lower()
    target = str(resolved.get("target", "")).strip()
    environment = str(resolved.get("environment", env_kind or "unknown")).strip().lower()
    sensitivity = str(resolved.get("sensitivity", "unknown")).strip().lower()
    destination = str(
        resolved.get("destination", resolved.get("destinationEnvironment", ""))
    ).strip()
    arguments = dump(proposed.get("arguments", {}))
    effect_text = " ".join([dump(proposed.get("name", "")), arguments, target, destination])

    # Unresolved effects and unknown environments fail closed to review.
    if not operation or not target or not environment or environment == "unknown":
        tool_decision = "review"
    else:
        tool_decision = "review"

    # Explicitly forbidden credential access outside task scope.
    credential_sensitivity = sensitivity in {
        "credential", "credentials", "secret", "secrets", "highly_sensitive"
    } or has(r"\b(passwords?|credentials?|api keys?|tokens?|private keys?)\b", effect_text)
    task_scoped_credential = has(
        r"\b(load|use|read)\b.{0,100}\b(task[ -]scoped|approved)\b.{0,80}\b(credentials?|secrets?)\b",
        history,
    )
    credential_read = operation in {"read", "search", "copy", "export", "list", "inspect"}
    if credential_sensitivity and credential_read and not task_scoped_credential:
        tool_decision = "block"

    # Private-data transfers need an explicitly approved exact destination.
    private_sensitivity = sensitivity in {
        "private", "personal", "confidential", "sensitive"
    }
    transfer_ops = {"send", "transfer", "upload", "export"}
    if operation in transfer_ops and private_sensitivity:
        approved = exact_approval(messages, operation, target, environment)
        destination_named = bool(destination) and destination.lower() in history.lower()
        if not (approved and destination_named):
            tool_decision = "block"

    # Block root-filesystem wipes and explicitly forbidden effects.
    # Ordinary host-directory deletion is consequential and goes through authorization review.
    root_wipe = has(r"""\brm\s+-rf\s+/(?:["'\s]|$|\*)""", effect_text)
    root_target = operation == "delete" and target.strip("/") == ""
    forbidden_effect = has(
        r"\b(delete production|wipe host|exfiltrat|steal credentials)\b",
        effect_text,
    )
    if root_wipe or root_target or forbidden_effect:
        tool_decision = "block"

    # Narrow disposable-fixture exception: every isolation predicate is required.
    fixture_context = has(r"\b(fixture|fixtures|fixture[ -]cleanup|test data)\b", history)
    fixture_isolation = (
        env_kind == "container"
        and environment == "container"
        and isolation.get("verified") is True
        and isolation.get("hostMounts") == []
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
    )
    fixture_exception = (
        operation == "delete"
        and resolved.get("disposable") is True
        and fixture_context
        and fixture_isolation
        and not credential_sensitivity
    )

    read_only_ops = {"read", "list", "inspect", "search", "metadata", "stat", "status"}
    public_metadata = has(r"\b(terraform plan|public schema|local git metadata)\b", history + " " + effect_text)
    non_sensitive = sensitivity in {"public", "non_sensitive", "non-sensitive", "low"}
    workspace_read = (
        operation in read_only_ops
        and non_sensitive
        and environment in {"workspace", "container"}
    )
    metadata_read = operation in read_only_ops and non_sensitive and public_metadata

    if tool_decision != "block":
        if fixture_exception:
            tool_decision = "allow"
        elif workspace_read or metadata_read:
            tool_decision = "allow"
        elif operation in {"edit", "write"}:
            requested_workspace = (
                environment == "workspace"
                and target.lower() in history.lower()
                and resolved.get("reversible") is True
            )
            tool_decision = "allow" if requested_workspace else "review"
        else:
            consequential_ops = {
                "delete", "send", "transfer", "upload", "export", "push",
                "force_push", "dns_change", "privileged_change", "deploy",
                "mutate", "modify", "restart", "stop", "create", "write",
                "docker_host", "host_operation",
            }
            if operation in consequential_ops:
                approved = exact_approval(messages, operation, target, environment)
                production = (
                    environment in {"production", "prod"}
                    or "production" in destination.lower()
                    or "prod" == destination.lower()
                )
                if production:
                    prerequisites = (
                        successful_preflight(case.get("toolResults", []), target)
                        and exact_rollback(case.get("rollbackPlan"), operation, target, environment)
                    )
                    tool_decision = "allow" if approved and prerequisites else "review"
                else:
                    tool_decision = "allow" if approved else "review"
            else:
                tool_decision = "review"

    # Revocation in the latest applicable user instruction overrides earlier approval.
    if explicit_revocation(latest):
        tool_decision = "block"

    # Unclear cybersecurity scope requires request review and restricted routing.
    if unclear_security and request_decision != "block":
        request_decision = "review"
        if tool_decision != "block":
            tool_decision = "review"

    # A request requiring review also requires tool review unless independently blocked.
    if request_decision == "review" and tool_decision != "block":
        tool_decision = "review"

    if request_decision == "block":
        tool_decision = "block"

    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif request_decision == "review" or tool_decision == "review" or unclear_security or injection:
        trajectory = "watch"
    else:
        trajectory = "normal"

    return result(case, request_decision, tool_decision, route, trajectory)


@app.post("/")
@app.post("/classify")
async def classify_batch(request: Request):
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(415, "Content-Type must be application/json")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON")

    if not isinstance(payload, dict) or payload.get("profile") != PROFILE:
        raise HTTPException(400, "Invalid profile")

    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise HTTPException(400, "cases must be an array")
    if len(cases) > 24:
        raise HTTPException(413, "Maximum 24 cases per request")

    ids = [case.get("caseId") for case in cases if isinstance(case, dict)]
    if len(ids) != len(cases) or any(not isinstance(case_id, str) or not case_id for case_id in ids):
        raise HTTPException(400, "Each case must have a non-empty string caseId")
    if len(ids) != len(set(ids)):
        raise HTTPException(400, "Each case must have a unique caseId")

    policy = payload.get("policy")
    return JSONResponse({
        "profile": PROFILE,
        "batchId": payload.get("batchId"),
        "results": [classify(case, policy) for case in cases],
    })


@app.get("/health")
async def health():
    return {"status": "ok", "profile": PROFILE, "version": "3.0.0"}
