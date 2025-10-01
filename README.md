# SchemaSentry
**GraphQL Schema Static Audit Tool**

SchemaSentry is a lightweight Python tool for **static auditing of GraphQL schemas**.  
It analyzes an introspection JSON dump and highlights potentially risky elements such as:  
- Suspicious mutations (`create`, `delete`, `reset`, `impersonate`, etc.)  
- Sensitive field or argument names (`password`, `token`, `secret`, etc.)  
- File upload scalars (`Upload`, `File`, `Binary`)  
- Free-text filters (`filter`, `search`, `query`, etc.)  
- Deprecated items  
- Sensitive data references in object or input types  

The goal is to help security testers quickly spot **“juicy” schema elements** for deeper investigation.  

---

## Features
- Detects risky mutation verbs  
- Flags sensitive fields & arguments  
- Identifies file-upload capability  
- Finds filters & free-text inputs  
- Lists deprecated items for review  
- Generates a detailed report (`schema_audit_report.txt`)  

---

## How to Use

### 1. Dump the GraphQL Schema
If introspection is enabled, you can retrieve the schema with a curl command:

```bash
curl -s -X POST "https://target-site/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } directives { name description locations args { ...InputValue } } } } fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }"}' \
  > schema.json

## Run Audit

...bash
python schemasentry.py schema.json
...

## Review the Results

Console summary of suspicious findings
Full detailed report in schema_audit_report.txt
