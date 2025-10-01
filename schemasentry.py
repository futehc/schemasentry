#!/usr/bin/env python3
"""
GraphQL Schema Static Audit Script
Author: Mitch
Purpose: Analyze a GraphQL introspection JSON (schema.json) for potential "juicy" or risky schema elements.
         Flags suspicious mutations, sensitive field/arg names, Upload scalar, free-text filters, deprecated items.
Usage: python graphql_schema_audit.py schema.json
Output: schema_audit_report.txt (detailed), console summary
"""

import sys
import json
import re

# Keywords to detect potentially risky mutations
SUSPICIOUS_VERBS = [
    "create", "delete", "remove", "update", "set", "reset", "grant", "revoke", "upload",
    "import", "export", "exec", "run", "execute", "enable", "disable", "restore", "purge",
    "truncate", "shutdown", "restart", "impersonate", "assume"
]

# Keywords to detect sensitive fields or arguments
SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "token", "secret", "credential", "credentials", "apiKey", "apikey",
    "session", "cookie", "jwt", "auth", "ssn", "socialsecurity", "card", "credit", "cvv", "pin",
    "email", "phone", "telephone", "address", "location", "geolocation", "salary"
]

# Keywords to detect filter/search/free-text arguments
POTENTIAL_FILTER_KEYWORDS = ["filter", "query", "where", "search", "match", "pattern", "q", "term"]

def load_schema(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def unwrap_type(t):
    # Recursively get inner named type
    while t and t.get("ofType"):
        t = t["ofType"]
    return t.get("name") if t else None

def name_contains_any(name, keywords):
    if not name: return False
    nl = name.lower()
    return any(k.lower() in nl for k in keywords)

def collect_types(schema):
    return {t.get("name"): t for t in schema.get("data", {}).get("__schema", {}).get("types", [])}

def find_root_types(schema):
    s = schema.get("data", {}).get("__schema", {})
    query_type = s.get("queryType")
    mutation_type = s.get("mutationType")
    subscription_type = s.get("subscriptionType")
    qname = query_type.get("name") if query_type else None
    mname = mutation_type.get("name") if mutation_type else None
    sname = subscription_type.get("name") if subscription_type else None
    return qname, mname, sname


def analyze(schema):
    report = []
    types = collect_types(schema)
    qname, mname, sname = find_root_types(schema)
    report.append(f"Root types: Query={qname}  Mutation={mname}  Subscription={sname}\n")

    suspicious = {
        "mutations_with_verbs": [],
        "sensitive_names": [],
        "upload_scalar": False,
        "fields_with_sensitive_args": [],
        "types_referencing_sensitive_strings": [],
        "filters_or_free_text_args": [],
        "deprecated_items": []
    }

    # Detect Upload/File scalar
    for tname, t in types.items():
        if t.get("kind") == "SCALAR" and tname.lower() in ("upload", "file", "binary"):
            suspicious["upload_scalar"] = True
            report.append(f"[!] Found scalar suggesting file upload: {tname}")

    # Inspect fields
    def inspect_fields(root_name, role):
        if not root_name or root_name not in types:
            return
        root = types[root_name]
        for f in root.get("fields", []) or []:
            fname = f.get("name")
            # Check verbs in name
            for v in SUSPICIOUS_VERBS:
                if re.search(rf"\b{re.escape(v)}", fname, re.IGNORECASE):
                    suspicious["mutations_with_verbs"].append((role, fname, v))
                    break
            # Check for sensitive keywords in field name
            if name_contains_any(fname, SENSITIVE_KEYWORDS):
                suspicious["sensitive_names"].append((role, fname, "field name contains sensitive keyword"))
            # Check args
            for arg in f.get("args", []) or []:
                aname = arg.get("name")
                atype = unwrap_type(arg.get("type")) or ""
                if name_contains_any(aname, SENSITIVE_KEYWORDS) or name_contains_any(atype, SENSITIVE_KEYWORDS):
                    suspicious["fields_with_sensitive_args"].append((role, fname, aname, atype))
                if name_contains_any(aname, POTENTIAL_FILTER_KEYWORDS) or name_contains_any(fname, POTENTIAL_FILTER_KEYWORDS):
                    suspicious["filters_or_free_text_args"].append((role, fname, aname, atype))
            # Deprecated fields
            if f.get("isDeprecated"):
                suspicious["deprecated_items"].append((role, fname, f.get("deprecationReason")))

    inspect_fields(qname, "query")
    inspect_fields(mname, "mutation")
    inspect_fields(sname, "subscription")

    # Examine all types and input types for sensitive fields
    for tname, t in types.items():
        if t.get("kind") in ("OBJECT", "INPUT_OBJECT"):
            for field in (t.get("fields") or t.get("inputFields") or []):
                fname = field.get("name")
                ftype = unwrap_type(field.get("type") or field)
                if name_contains_any(fname, SENSITIVE_KEYWORDS) or name_contains_any(ftype, SENSITIVE_KEYWORDS):
                    suspicious["types_referencing_sensitive_strings"].append((tname, fname, ftype))
                if name_contains_any(fname, POTENTIAL_FILTER_KEYWORDS):
                    suspicious["filters_or_free_text_args"].append((tname, fname, "INPUT_FIELD", ftype))

    # Build human-readable report
    report.append("\nSummary of suspicious findings:\n")
    report.append(f"- File-upload scalar detected: {suspicious['upload_scalar']}\n")
    report.append(f"- Mutations/queries using risky verbs: {len(suspicious['mutations_with_verbs'])}\n")
    for role, fn, verb in suspicious['mutations_with_verbs']:
        report.append(f"  - {role.upper()} '{fn}' (matches verb '{verb}')")
    report.append(f"- Fields/args containing sensitive keywords: {len(suspicious['fields_with_sensitive_args'])}\n")
    for item in suspicious['fields_with_sensitive_args'][:50]:
        report.append(f"  - {item}")
    report.append(f"- Types/fields referencing sensitive data: {len(suspicious['types_referencing_sensitive_strings'])}\n")
    for item in suspicious['types_referencing_sensitive_strings'][:50]:
        report.append(f"  - {item}")
    report.append(f"- Fields with filter/search/free-text args: {len(suspicious['filters_or_free_text_args'])}\n")
    for item in suspicious['filters_or_free_text_args'][:50]:
        report.append(f"  - {item}")
    report.append(f"- Deprecated fields: {len(suspicious['deprecated_items'])}\n")
    for item in suspicious['deprecated_items'][:50]:
        report.append(f"  - {item}")

    # List mutations and args for manual review
    if mname and mname in types:
        report.append("\nList of mutations (name -> args):")
        for f in types[mname].get("fields") or []:
            args = [(a.get("name"), unwrap_type(a.get("type"))) for a in f.get("args", [])]
            report.append(f"  - {f.get('name')}: {args}")

    out = "\n".join(report)
    with open("schema_audit_report.txt", "w", encoding="utf-8") as rf:
        rf.write(out)

    # Print console summary
    print("=== GraphQL Schema Audit Summary ===")
    print(f"Root Query: {qname}, Mutation: {mname}, Subscription: {sname}")
    print(f"Upload scalar detected: {suspicious['upload_scalar']}")
    print(f"Potential risky mutations/queries: {len(suspicious['mutations_with_verbs'])}")
    print(f"Sensitive-looking fields/args: {len(suspicious['fields_with_sensitive_args'])}")
    print(f"Potential filters/free-text args: {len(suspicious['filters_or_free_text_args'])}")
    print(f"Types referencing sensitive names: {len(suspicious['types_referencing_sensitive_strings'])}")
    print(f"Deprecated items: {len(suspicious['deprecated_items'])}")
    print("\nFull detailed report written to schema_audit_report.txt")
    print("Review the report and attempt targeted tests against the live endpoint for flagged items.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python graphql_schema_audit.py <schema.json>")
        sys.exit(1)
    schema_path = sys.argv[1]
    schema = load_schema(schema_path)
    analyze(schema)
