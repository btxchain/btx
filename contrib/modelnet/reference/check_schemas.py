"""Validate v1.1 schema shapes and fixtures, NOT signatures or BTX behavior."""
from pathlib import Path
import copy
import json
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

def run():
    checks = []
    schemas = {}
    for path in sorted((ROOT / 'schemas').glob('*.schema.json')):
        schema = json.loads(path.read_text())
        Draft202012Validator.check_schema(schema)
        schemas[path.name.removesuffix('.schema.json')] = Draft202012Validator(schema)
        checks.append({'name': 'schema_meta:' + path.name, 'result': 'PASS'})
    vectors = json.loads((ROOT / 'evidence/v1.1-vectors.json').read_text())
    for row in vectors['record_vectors']:
        validator = schemas[row['name']]
        validator.validate(row['body'])
        checks.append({'name': 'record_example:' + row['name'], 'result': 'PASS'})
        bad = copy.deepcopy(row['body'])
        bad['unrecognized_required_field'] = True
        assert list(validator.iter_errors(bad)), 'extra field unexpectedly accepted'
        checks.append({'name': 'record_unknown_field_rejected:' + row['name'], 'result': 'PASS'})
    uri_validator = schemas['resource-reference']
    for row in vectors['resource_vectors']:
        uri_validator.validate(row['uri'])
        checks.append({'name': 'uri_shape:' + row['name'], 'result': 'PASS'})
    for label, value in [('short','btx://abc'), ('path','btx://m/abc'), ('bad_scheme','https://abc')]:
        assert list(uri_validator.iter_errors(value))
        checks.append({'name':'uri_shape_rejected:' + label, 'result':'PASS'})
    report = {'scope':'JSON Schema meta-validation and example/negative SHAPE checks only. No cryptographic signatures, URI checksum validation or production BTX tests.',
              'schema_files':len(schemas), 'checks_run':len(checks), 'checks_passed':len(checks), 'checks':checks}
    (ROOT / 'evidence/schema-checks.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{len(checks)} schema/fixture checks PASS; {len(schemas)} schemas")

if __name__ == '__main__':
    run()
