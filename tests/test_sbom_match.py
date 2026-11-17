import pytest

from supplychain.sbom_match import (
    normalize_purl,
    parse_version,
    version_in_range,
    merge_aliases,
    transitive_deps,
    min_fixed_version,
    parse_cvss
)


def test_purl_lower():
    assert normalize_purl('pkg:NPM/Lodash@4.17.21') == 'pkg:npm/lodash@4.17.21'

def test_purl_namespace():
    assert normalize_purl('pkg:npm/%40scope/name@1.0.0') == 'pkg:npm/%40scope/name@1.0.0'

def test_parse_version():
    assert parse_version('1.0.10') == (1, 0, 10)

def test_version_order():
    assert parse_version('1.0.10') > parse_version('1.0.2')

def test_range_inclusive():
    assert version_in_range('1.2.3', '>=1.2.3 <2.0.0') is True

def test_range_exclusive():
    assert version_in_range('2.0.0', '>=1.2.3 <2.0.0') is False

def test_transitive():
    assert transitive_deps({'a': ['b'], 'b': ['c']}, 'a') == {'a', 'b', 'c'}

def test_transitive_optional():
    assert transitive_deps({'a': ['b']}, 'a', include_optional=True, optional={'a': ['x']}) == {'a', 'b', 'x'}

def test_aliases():
    assert merge_aliases({'CVE-1': ['GHSA-1'], 'GHSA-1': ['OSV-1']}) == {'CVE-1', 'GHSA-1', 'OSV-1'}

def test_cvss():
    assert parse_cvss('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')['AV'] == 'N'

def test_min_fix():
    assert min_fixed_version({'fixed': ['1.2.4', '1.3.0']}, {'max': '1.2.x'}) == '1.2.4'

def test_no_fix():
    assert min_fixed_version({'fixed': []}, {}) is None

def test_empty_transitive():
    assert transitive_deps({}, 'a') == {'a'}

def test_cycle_transitive():
    assert transitive_deps({'a': ['b'], 'b': ['a']}, 'a') == {'a', 'b'}

def test_bad_purl():
    assert normalize_purl('not-a-purl') is None
