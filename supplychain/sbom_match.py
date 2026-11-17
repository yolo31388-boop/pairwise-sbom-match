"""SBOM 匹配核心工具：purl 规范化、语义版本、依赖图、别名合并、CVSS、修复版本选择。"""

import re


def normalize_purl(purl):
    """规范化 package-url：type 与 name 小写，保留命名空间与版本。

    非法 purl 返回 None。
    """
    if not isinstance(purl, str):
        return None
    m = re.match(
        r'^pkg:(?P<type>[a-zA-Z0-9.+-]+)/(?P<rest>[^\s]+)$', purl
    )
    if not m:
        return None
    ptype = m.group('type').lower()
    rest = m.group('rest')

    qualifiers = ''
    if '?' in rest:
        rest, qualifiers = rest.split('?', 1)
        qualifiers = '?' + qualifiers

    version = ''
    if '@' in rest:
        rest, version = rest.rsplit('@', 1)
        version = '@' + version

    if '/' in rest:
        namespace, name = rest.rsplit('/', 1)
        namespace = namespace.lower() + '/'
    else:
        namespace, name = '', rest

    name = name.lower()
    if not name:
        return None
    return 'pkg:{}/{}{}{}{}'.format(ptype, namespace, name, version, qualifiers)


def parse_version(version):
    """把 '1.0.10' 解析为可比较的整数元组 (1, 0, 10)。"""
    parts = []
    for piece in str(version).strip().lstrip('v').split('.'):
        num = re.match(r'\d+', piece)
        parts.append(int(num.group()) if num else 0)
    return tuple(parts)


def _pad(v, n):
    return tuple(v) + (0,) * (n - len(v))


def version_in_range(version, range_expr):
    """判断 version 是否满足如 '>=1.2.3 <2.0.0' 的区间（空格分隔的 comparator 取交集）。"""
    v = parse_version(version)
    for comp in str(range_expr).split():
        m = re.match(r'(>=|<=|>|<|=|==)?\s*(.+)', comp)
        if not m:
            return False
        op = m.group(1) or '=='
        target = parse_version(m.group(2))
        n = max(len(v), len(target))
        a, b = _pad(v, n), _pad(target, n)
        if op in ('=', '==') and not a == b:
            return False
        if op == '>=' and not a >= b:
            return False
        if op == '<=' and not a <= b:
            return False
        if op == '>' and not a > b:
            return False
        if op == '<' and not a < b:
            return False
    return True


def transitive_deps(graph, root, include_optional=False, optional=None):
    """从 root 出发遍历完整依赖图（含 optional/peer），返回含 root 的闭包集合。"""
    optional = optional or {}
    seen = {root}
    stack = [root]
    while stack:
        node = stack.pop()
        deps = list(graph.get(node, []))
        if include_optional:
            deps += list(optional.get(node, []))
        for dep in deps:
            if dep not in seen:
                seen.add(dep)
                stack.append(dep)
    return seen


def merge_aliases(aliases):
    """合并 CVE/GHSA/OSV 等别名映射，返回同一连通分量内的全部 ID。"""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    for key, values in aliases.items():
        find(key)
        for value in values:
            union(key, value)

    if not parent:
        return set()
    # 返回第一个 key 所在的连通分量
    root = find(next(iter(aliases)))
    return {x for x in parent if find(x) == root}


def parse_cvss(vector):
    """解析 CVSS 向量字符串为 {指标: 值} 字典，容忍 'CVSS:3.1/' 前缀。"""
    result = {}
    for part in str(vector).split('/'):
        if ':' not in part:
            continue
        key, value = part.split(':', 1)
        if key == 'CVSS':  # 版本前缀，如 CVSS:3.1
            continue
        result[key] = value
    return result


def min_fixed_version(advisory, constraints=None):
    """在约束（如 {'max': '1.2.x'}）内选择最小的修复版本；无可用版本返回 None。"""
    fixed = advisory.get('fixed') or []
    if not fixed:
        return None
    constraints = constraints or {}
    max_pattern = constraints.get('max')

    def allowed(v):
        if not max_pattern:
            return True
        pattern_parts = str(max_pattern).split('.')
        version_parts = str(v).split('.')
        for i, p in enumerate(pattern_parts):
            if p in ('x', '*'):
                continue
            if i >= len(version_parts) or version_parts[i] != p:
                return False
        return True

    candidates = [v for v in fixed if allowed(v)]
    if not candidates:
        return None
    return min(candidates, key=parse_version)
