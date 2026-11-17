# pairwise-sbom-match

依赖扫描报告一打开，满屏都是误报和漏报：purl 没有规范化大小写和命名空间，同一个包被拆成两条；版本区间只做字符串比较，1.0.10 被判定低于 1.0.2；传递依赖只看 lockfile 顶层，optional 和 peer 依赖整个丢失；漏洞匹配只看 CVE 主键，GHSA 和 OSV 的别名没有合并；CVSS 向量解析把 AV:N 当成 AV:L，评分算反；修复建议直接取最新版，忽略 breaking change 和运行时约束。supplychain/sbom_match.py 是核心，tests/test_sbom_match.py 15个红。要修的是：purl 规范化；语义版本区间；完整依赖图；别名合并；CVSS 解析；约束内最小升级。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
