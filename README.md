# k8s-netpol-audit

k8s-netpol-audit reads `kubectl get ... -o json` output (a List or single objects) and checks pod network isolation: namespaces that run workloads but have no NetworkPolicy, namespaces with policies but no default-deny for ingress or egress, ingress rules open to `0.0.0.0/0`, and rules that allow every source or destination.

**Live demo:** https://jvch0512.github.io/k8s-netpol-audit/ (Synthetic data.)

Nim, standard library only. The demo page is rendered from the tool's `--tsv` output by `scripts/site.py` (Python 3, only needed to regenerate the page).

## Use

```bash
make build
bin/k8s-netpol-audit examples
bin/k8s-netpol-audit ./dumps --tsv
bin/k8s-netpol-audit ./dumps --fail-on high       # exit 1 on any high finding
```

Exit codes: 0 ok, 1 findings at or above `--fail-on`, 2 bad input. Output is human text by default and TSV with `--tsv` (`# N files, M findings`, then `SEVERITY<TAB>RULE<TAB>WHERE<TAB>MESSAGE`).

| Rule | Severity | What it catches |
|---|---|---|
| KNP001 | high | a namespace with workloads and no NetworkPolicy at all |
| KNP002 | medium | a namespace with policies but no default-deny ingress policy |
| KNP003 | low | a namespace with policies but no default-deny egress policy |
| KNP004 | high | an ingress rule from an ipBlock of 0.0.0.0/0 or ::/0 |
| KNP005 | medium | an ingress rule with no `from`, which allows every source |
| KNP006 | low | an egress rule with no `to`, which allows every destination |
| KNP000 | info | the file is not valid JSON or has no Kubernetes objects |

See [examples](examples) and [docs/sample-output.txt](docs/sample-output.txt).

## Limits

- It reads the JSON as dumped. YAML manifests must be converted first, for example with `kubectl get ... -o json`.
- Namespaces `kube-system`, `kube-public` and `kube-node-lease` are not checked for missing policies.
- Namespaces are taken from `metadata.namespace`; objects without one count as `default`.
- A default-deny policy is one with an empty `podSelector` and the matching `policyTypes` entry and no rules for that direction.
- CNI behaviour, `CiliumNetworkPolicy` and `CalicoNetworkPolicy` objects are not read.

## Where it fits

Kubernetes security reviews, CKS style checks and quick looks at a customer cluster dump.

## Tests

```bash
make test    # A Nim test program: every rule on good and bad dumps, default-deny detection, ipBlock handling, hostile JSON, fuzzing and CLI exit codes
```

MIT.
