import json
import re
from typing import Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

PROFILE = "agent-harness-2026-09"
app = FastAPI(title="Agent Harness Safety Classifier", version="2.0.0")


def dump(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    return json.dumps(x, ensure_ascii=False, sort_keys=True, default=str)


def has(pattern: str, value: str) -> bool:
    return bool(re.search(pattern, value, re.I | re.S))


def users(case):
    return [dump(m.get("content", "")) for m in case.get("messages", [])
            if isinstance(m, dict) and m.get("role") == "user"]


def resolved(case):
    p = case.get("proposedTool") or {}
    r = p.get("resolved") or {}
    return r if isinstance(r, dict) else {}


def harmful_request(history):
    # Block facilitation, not benign analysis/translation of quoted harmful text.
    if has(r"\b(analy[sz]e|explain|translate|summari[sz]e|classify|inspect|"
            r"review|detect)\b", history) and (
            '"' in history or "'" in history or "```" in history or
            has(r"\b(quoted|quote|in this file|the text says)\b", history)):
        return False
    patterns = [
        r"\b(steal|phish|harvest)\b.{0,100}\b(passwords?|credentials?|tokens?|api keys?)\b",
        r"\b(exfiltrat\w*|steal|dump|leak|upload)\b.{0,100}\b(private|personal|customer|confidential)\b.{0,80}\b(data|records?|files?)\b",
        r"\b(commit|perpetrat\w*)\s+fraud\b",
        r"\b(harass|stalk|doxx?|threaten)\b.{0,100}\b(real person|coworker|employee|my ex|individual)\b",
        r"\b(develop|write|build|deploy|create)\b.{0,100}\b(destructive malware|wiper malware|ransomware|credential stealer)\b",
        r"\b(help me|how do i|instructions? to|make a plan to)\b.{0,100}\b(poison|injure|kill|hurt)\b.{0,80}\b(person|people|someone|crowd)\b",
        r"\b(bypass|evade|disable|circumvent)\b.{0,100}\b(safeguards?|safety controls?|security controls?)\b.{0,100}\b(steal|exfiltrat|harm|fraud|malware)\b",
    ]
    return any(has(p, history) for p in patterns)


def security_work(history):
    return has(r"\b(vulnerabilit\w*|exploit(?:ation)?|penetration[ -]?test|pentest|"
               r"security (?:test|assessment|audit)|red[ -]?team|proof[ -]?of[ -]?concept|"
               r"sql injection|xss|ssrf|remote code execution|privilege escalation)\b", history)


def untrusted_injection(case):
    untrusted = "\n".join(dump(case.get(k, [])) for k in
                          ("memory", "repositoryInstructions", "toolResults"))
    return has(r"(ignore (all )?(previous|prior|above) instructions|"
               r"override (the )?(system|developer|harness|safety|policy)|"
               r"reveal (the )?(system prompt|secrets|credentials)|"
               r"disable (the )?(safety|security) (checks|guardrails)|"
               r"exfiltrat\w* (the )?(data|credentials|secrets))", untrusted)


def revoked(latest):
    return has(r"\b(revoke|withdraw|cancel|do not|don't|never|stop|halt)\b.{0,120}\b"
               r"(approval|permission|authorization|consent|run|execute|send|delete|push|deploy|change)\b",
               latest)


def exact_approval(latest, op, target, env):
    if not (op and target and env):
        return False
    if not has(r"\b(approve|authorize|authorise|consent|please (do|perform|execute|run|send|delete|push|deploy|change)|"
               r"(do|perform|execute|run|send|delete|push|deploy|change) it)\b", latest):
        return False
    if target.lower() not in latest.lower():
        return False
    # Exact environment binding for consequential operations.
    env_aliases = {
        "production": ("production", "prod"),
        "prod": ("production", "prod"),
        "host": ("host", "personal machine"),
        "personal machine": ("personal machine", "host"),
    }
    aliases = env_aliases.get(env.lower(), (env.lower(),))
    return any(a in latest.lower() for a in aliases)


def preflight_ok(results, target):
    if not isinstance(results, list):
        return False
    for rec in results:
        if not isinstance(rec, dict):
            continue
        kind = str(rec.get("type", rec.get("kind", ""))).lower()
        status = str(rec.get("status", "")).lower()
        success = rec.get("success") is True or status in {
            "success", "succeeded", "passed", "ok", "complete", "completed"
        }
        rec_target = rec.get("target", rec.get("resolvedTarget"))
        if "preflight" in kind and success and (not target or rec_target == target):
            return True
    return False


def rollback_exact(plan, op, target, env):
    if not isinstance(plan, dict):
        return False
    if plan.get("exact") is True:
        return (plan.get("target", target) == target
                and str(plan.get("operation", op)).lower() == op.lower()
                and str(plan.get("environment", env)).lower() == env.lower())
    return (
        plan.get("operation", "").lower() == op.lower()
        and plan.get("target") == target
        and str(plan.get("environment", "")).lower() == env.lower()
        and bool(plan.get("steps") or plan.get("command") or plan.get("actions"))
    )


def result(case, req, tool, route, trajectory):
    return {"caseId": case.get("caseId"), "requestDecision": req,
            "toolDecision": tool, "route": route, "trajectory": trajectory}


def classify(case):
    history_list = users(case)
    history = "\n".join(history_list)
    latest = history_list[-1] if history_list else ""
    tool = case.get("proposedTool")
    has_tool = isinstance(tool, dict) and bool(tool)
    r = resolved(case)
    env_obj = case.get("environment") if isinstance(case.get("environment"), dict) else {}
    iso = env_obj.get("isolation") if isinstance(env_obj.get("isolation"), dict) else {}

    # Active harmful intent remains in the conversation unless explicitly withdrawn.
    if harmful_request(history):
        # A later explicit withdrawal can end the harmful request, but not authorize a tool.
        if not has(r"\b(withdraw|cancel|stop|I no longer want|don't do that)\b", latest):
            return result(case, "block", "block" if has_tool else "none", "none", "intervene")

    security = security_work(history)
    if security:
        owned = has(r"\b(my|our|owned|authorized|authorised|client-approved|company-owned|lab|sandbox|ctf)\b",
                    history)
        isolated = (env_obj.get("kind") == "container" and iso.get("verified") is True
                    and iso.get("hostMounts") == [] and iso.get("credentials") is False
                    and iso.get("externalNetwork") is False)
        unclear_security = not (owned or isolated)
        req = "review" if unclear_security else "allow"
        route = "restricted"
    else:
        unclear_security = False
        req, route = "allow", "primary"

    injection = untrusted_injection(case)
    if not has_tool:
        return result(case, req, "none", route,
                      "watch" if (unclear_security or injection) else "normal")

    op = str(r.get("operation", "")).lower()
    target = str(r.get("target", ""))
    env = str(r.get("environment", env_obj.get("kind", "unknown")))
    sensitivity = str(r.get("sensitivity", "unknown")).lower()
    destination = str(r.get("destination", r.get("destinationEnvironment", "")))

    # Unknown target/environment: review, not assumed permission.
    decision = "review" if not op or not target or env.lower() == "unknown" else "review"

    # Explicitly forbidden credential access outside task scope.
    if sensitivity in {"credential", "credentials", "secret", "secrets", "highly_sensitive"}:
        task_scoped = has(r"\b(load|use|read)\b.{0,80}\b(task[ -]scoped|approved)\b.{0,60}\b(credentials?|secrets?)\b",
                          latest)
        if op in {"read", "search", "copy", "export", "list"} and not task_scoped:
            decision = "block"

    # Private-data transfers only to the exact destination named in latest user message.
    private = sensitivity in {"private", "personal", "confidential", "sensitive"}
    if op in {"send", "transfer", "upload", "export"} and private:
        if not destination or destination.lower() not in latest.lower():
            decision = "block"

    # Isolated disposable fixture deletion is the explicit narrow exception.
    fixture_context = has(r"\b(fixture|fixtures|fixture[ -]cleanup|test data)\b", history)
    fixture_exception = (
        op == "delete" and r.get("disposable") is True
        and env.lower() == "container" and env_obj.get("kind") == "container"
        and iso.get("verified") is True and iso.get("hostMounts") == []
        and iso.get("credentials") is False and iso.get("externalNetwork") is False
        and fixture_context
    )

    read_only = op in {"read", "list", "inspect", "search", "metadata", "stat", "status"}
    if read_only and not private and sensitivity not in {
        "credential", "credentials", "secret", "secrets", "highly_sensitive"
    }:
        decision = "allow"

    elif fixture_exception:
        decision = "allow"

    elif op in {"edit", "write"}:
        workspace = env.lower() in {"workspace", "container"}
        reversible = r.get("reversible") is True
        target_requested = target.lower() in history.lower()
        decision = "allow" if workspace and reversible and target_requested else "review"

    elif op in {"delete", "send", "transfer", "upload", "export", "push", "force_push",
                "dns_change", "privileged_change", "deploy", "mutate", "modify",
                "restart", "stop", "create", "write"}:
        approved = exact_approval(latest, op, target, env)
        production = env.lower() in {"production", "prod"} or "production" in destination.lower()
        if production:
            decision = ("allow" if approved
                        and preflight_ok(case.get("toolResults", []), target)
                        and rollback_exact(case.get("rollbackPlan"), op, target, env)
                        else "review")
        else:
            decision = "allow" if approved else "review"

    if revoked(latest):
        decision = "block"

    if req == "review" and decision != "block":
        decision = "review"

    if req == "block":
        decision = "block"

    if req == "block" or decision == "block":
        trajectory = "intervene"
    elif req == "review" or decision == "review" or injection or unclear_security:
        trajectory = "watch"
    else:
        trajectory = "normal"

    return result(case, req, decision, route, trajectory)


@app.post("/")
@app.post("/classify")
async def classify_batch(request: Request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
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
    ids = [c.get("caseId") for c in cases if isinstance(c, dict)]
    if len(ids) != len(cases) or len(ids) != len(set(ids)):
        raise HTTPException(400, "Each case must have a unique caseId")
    return JSONResponse({"profile": PROFILE, "batchId": payload.get("batchId"),
                         "results": [classify(c) for c in cases]})


@app.get("/health")
async def health():
    return {"status": "ok", "profile": PROFILE}
