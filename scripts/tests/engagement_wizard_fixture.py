"""Fictional answers for the complete console questionnaire; never sends traffic."""

import datetime as dt


def fixture_answerer(engine, trace):
    now = dt.datetime.now(dt.timezone.utc)
    replies = {
        "Engagement name": "Wizard Practice",
        "Client/system owner name": "Fixture Owner",
        "Engagement type -": "6",
        "Lead tester name": "Fixture Tester",
        "Written permission / contract reference": "FIXTURE-ROE",
        "System owner": "Fixture Owner",
        "Authorizing person and role": "Fixture Authorizer",
        "Authorization starts": (now - dt.timedelta(days=1)).isoformat(),
        "Authorization ends": (now + dt.timedelta(days=1)).isoformat(),
        "Environment -": "5",
        "Authorization evidence location": "fixture://permission",
        "Authorization evidence SHA-256": "a" * 64,
        "Primary point-of-contact name": "Fixture Contact",
        "Primary point-of-contact method": "fixture",
        "Technical contact name": "Fixture Contact",
        "Technical contact method": "fixture",
        "Emergency/stop contact name": "Fixture Contact",
        "Emergency/stop contact method": "fixture",
        "Breach-escalation contact name": "Fixture Contact",
        "Breach-escalation contact method": "fixture",
        "Breach discovery escalation procedure": "Pause testing and contact the fixture owner.",
        "Target value": "192.0.2.4",
        "Automated exploitation policy -": "2",
        "Allowed action numbers": ",".join(
            str(engine.ACTIONS.index(v) + 1)
            for v in ("network.discovery", "web.active")
        ),
        "Daily start time": "00:00",
        "Daily end time": "23:59",
        "Approved source IPs": "198.51.100.10",
        "TCP ports/ranges": "80,443",
        "Approved output encryption standard/method": "Approved organization encryption policy",
        "Approved report delivery method": "Approved client transfer channel",
    }
    optional = (
        "Access/hosting location details",
        "Authorization evidence SHA-256",
        "Note",
        "Action numbers requiring approval",
        "Maximum bandwidth",
        "Stop conditions",
        "Notes",
    )
    target_types = iter(["1", "0", "0"])

    def answer(line):
        if line.startswith("Target type number"):
            value = next(target_types)
        else:
            value = None
            for prefix, response in replies.items():
                if line.startswith(prefix):
                    value = response
                    break
            if value is None:
                if "[" in line or line.startswith(optional):
                    value = ""
                else:
                    raise AssertionError("Missing fixture answer: " + line)
        trace.append((line, value))
        return value

    return answer
