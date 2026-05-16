import json
import urllib.request
import urllib.error

from security.validators import is_private_ip
from security.common import mark_run_started, append_output_chunk, mark_run_completed
from security.ai_explain import explain_tool_output


def get_public_wan_ip(timeout=10):
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode().strip()
    except Exception:
        return None


def query_shodan(ip: str, api_key: str, timeout=20) -> dict:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        return {"error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"error": str(e)}


def run_shodan_check(*, run_id, target_ip=None, query_ip=None, api_key):
    from app.database import SessionLocal
    from models.tables import ShodanExposureResult

    db = SessionLocal()
    try:
        mark_run_started(db, run_id, command=["shodan_api"])

        is_private = bool(target_ip and is_private_ip(target_ip))

        if query_ip:
            final_ip = query_ip
        elif is_private:
            append_output_chunk(db, run_id, stream="status",
                content=f"Target {target_ip} is a private IP. Checking your public WAN IP instead...\n")
            final_ip = get_public_wan_ip()
            if not final_ip:
                mark_run_completed(db, run_id, status="failed",
                    error_message="Could not determine public WAN IP.")
                return
        else:
            final_ip = target_ip

        append_output_chunk(db, run_id, stream="status", content=f"Querying Shodan for {final_ip}...\n")

        result = query_shodan(final_ip, api_key)
        append_output_chunk(db, run_id, stream="stdout", content=json.dumps(result, indent=2))

        error  = result.get("error")
        ports  = result.get("ports", [])
        vulns  = result.get("vulns", {})
        exposed = bool(ports or result.get("data"))

        if error == "not_found":
            risk = "info"
        elif vulns:
            risk = "high"
        elif exposed:
            risk = "medium"
        else:
            risk = "low"

        db.add(ShodanExposureResult(
            run_id           = run_id,
            target_ip        = target_ip,
            query_ip         = final_ip,
            is_private_target= is_private,
            exposed          = exposed,
            org              = result.get("org"),
            isp              = result.get("isp"),
            country          = result.get("country_name"),
            ports_json       = json.dumps(ports),
            vulns_json       = json.dumps(list(vulns.keys())) if vulns else "[]",
            raw_json         = json.dumps(result),
        ))
        db.commit()

        explain_tool_output(
            db, run_id=run_id, tool="shodan",
            target=target_ip or final_ip,
            command=["shodan_api"],
            raw_output=json.dumps(result, indent=2),
        )

        mark_run_completed(db, run_id,
            status="succeeded" if not error else "failed",
            risk_level=risk,
            raw_output_text=json.dumps(result, indent=2),
        )

    except Exception as e:
        try:
            append_output_chunk(db, run_id, stream="stderr", content=f"\nError: {e}\n")
            mark_run_completed(db, run_id, status="failed", error_message=str(e))
        except Exception:
            pass
    finally:
        db.close()
