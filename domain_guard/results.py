import json

MAX_RESULT_BYTES = 65536
RAW_VALUE_BUDGET = 32768

def serialize(result):
    return json.dumps(result, ensure_ascii=True, allow_nan=False).encode("ascii")

def bound_report(report):
    if(len(serialize(report)) <= MAX_RESULT_BYTES):
        return report
    remaining = RAW_VALUE_BUDGET
    lookups = list(report["records"].values()) + [report[key] for key in ("spf", "dmarc", "mta_sts", "tlsrpt") if key in report]
    for lookup in lookups:
        values = []
        for value in lookup["values"]:
            size = len(serialize(value)) + 2
            if(size > remaining):
                break
            values.append(value)
            remaining -= size
        if(len(values) != len(lookup["values"])):
            lookup["values"] = values
            lookup["status"] = "incomplete"
            lookup["message"] = "Some records omitted because the report exceeded its output budget"
    report["status"] = "incomplete"
    if(len(serialize(report)) > MAX_RESULT_BYTES):
        # This is a last-resort bound for an unexpected oversized internal result.
        return {"schema_version": 1, "domain": report["domain"], "status": "incomplete", "addresses": report["addresses"], "records": {}, "checks": {"output": {"status": "incomplete", "message": "Report exceeded its output budget"}}}
    return report
