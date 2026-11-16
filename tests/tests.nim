import std/[strutils, sequtils, algorithm, random, json]
import netpol

var passed = 0
var failed = 0
proc check(ok: bool, name: string) =
  if ok: inc passed
  else:
    inc failed
    echo "FAIL: ", name

proc rules(text: string): string =
  audit(text, "t.json").mapIt(it.rule).sorted().join(",")

proc wl(ns: string, kind = "Deployment", name = "w"): string =
  """{"kind":"$1","metadata":{"name":"$2","namespace":"$3"}}""" % [kind, name, ns]

proc np(ns, name, spec: string): string =
  """{"kind":"NetworkPolicy","metadata":{"name":"$1","namespace":"$2"},"spec":$3}""" % [name, ns, spec]

proc lst(items: varargs[string]): string =
  """{"kind":"List","items":[""" & items.join(",") & "]}"

const
  denyIn = """{"podSelector":{},"policyTypes":["Ingress"]}"""
  denyEg = """{"podSelector":{},"policyTypes":["Egress"]}"""
  denyBoth = """{"podSelector":{},"policyTypes":["Ingress","Egress"]}"""

# clean
check(rules(lst(wl("a"), np("a", "d", denyBoth))) == "", "default deny both is clean")
check(rules(lst(np("a", "d", denyBoth))) == "", "policies only, no workloads")
check(rules(lst(wl("a"), np("a", "d", denyBoth), np("a", "x", """{"podSelector":{"matchLabels":{"a":"b"}},"policyTypes":["Ingress"],"ingress":[{"from":[{"podSelector":{}}]}]}"""))) == "", "scoped allow is clean")

# KNP001
check(rules(lst(wl("a"))) == "KNP001", "workload without policy")
check(audit(lst(wl("a")), "t")[0].sev == "high", "KNP001 is high")
for kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod", "ReplicationController"]:
  check(rules(lst(wl("a", kind))) == "KNP001", "workload kind " & kind)
check(rules(lst(wl("a", "Service"))) == "", "service is not a workload")
check(rules(lst(wl("kube-system"))) == "", "kube-system skipped")
check(rules(lst(wl("kube-public"))) == "", "kube-public skipped")
check(rules(lst(wl("kube-node-lease"))) == "", "kube-node-lease skipped")
check(rules(lst("""{"kind":"Deployment","metadata":{"name":"x"}}""")) == "KNP001", "no namespace is default")
check(audit(lst("""{"kind":"Deployment","metadata":{"name":"x"}}"""), "t")[0].where == "t#default", "default label")
check(rules(lst(wl("a"), wl("b"))) == "KNP001,KNP001", "two namespaces")
check(rules(lst(wl("a"), wl("a", "StatefulSet"))) == "KNP001", "one finding per namespace")

# KNP002 / KNP003
check(rules(lst(wl("a"), np("a", "p", denyEg))) == "KNP002", "only egress deny: no ingress deny")
check(rules(lst(wl("a"), np("a", "p", denyIn))) == "KNP003", "only ingress deny: no egress deny")
check(rules(lst(wl("a"), np("a", "p", """{"podSelector":{"matchLabels":{"a":"b"}},"policyTypes":["Ingress"]}"""))) == "KNP002,KNP003", "selective deny is not default deny")
check(rules(lst(wl("a"), np("a", "p", """{"podSelector":{"matchLabels":{}},"policyTypes":["Ingress"]}"""))) == "KNP003", "empty matchLabels is select all")
check(rules(lst(wl("a"), np("a", "p", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"podSelector":{}}]}]}"""))) == "KNP002,KNP003", "allow rules are not default deny")
check(rules(lst(wl("a"), np("a", "p", """{"podSelector":{}}"""))) == "KNP003", "no policyTypes defaults to ingress deny")
check(audit(lst(wl("a"), np("a", "p", denyEg)), "t")[0].sev == "medium", "KNP002 is medium")
check(audit(lst(wl("a"), np("a", "p", denyIn)), "t")[0].sev == "low", "KNP003 is low")
check(rules(lst(wl("a"), np("b", "p", denyBoth))) == "KNP001", "policy in another namespace does not count")
check(rules(lst(wl("a"), np("a", "p1", denyIn), np("a", "p2", denyEg))) == "", "deny split across two policies")

# KNP004
for cidr in ["0.0.0.0/0", "::/0"]:
  check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"ipBlock":{"cidr":"$1"}}]}]}""".replace("$1", cidr)))) == "KNP004", "ipBlock " & cidr)
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8"}}]}]}"""))) == "", "private ipBlock is fine")
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"ipBlock":{"cidr":"0.0.0.0/0","except":["10.0.0.0/8"]}}]}]}"""))) == "KNP004", "ipBlock with except still open")
check(audit(lst(wl("a"), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[{"ipBlock":{"cidr":"0.0.0.0/0"}}]}]}""")), "t")[0].sev == "high", "KNP004 is high")

# KNP005 / KNP006
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{}]}"""))) == "KNP005", "ingress {} allows all")
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"ports":[{"port":80}]}]}"""))) == "KNP005", "ports only allows all sources")
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Ingress"],"ingress":[{"from":[]}]}"""))) == "KNP005", "empty from allows all")
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Egress"],"egress":[{}]}"""))) == "KNP006", "egress {} allows all")
check(rules(lst(wl("a"), np("a", "p", denyBoth), np("a", "q", """{"podSelector":{},"policyTypes":["Egress"],"egress":[{"to":[{"podSelector":{}}]}]}"""))) == "", "scoped egress is fine")

# shapes
check(rules(wl("a")) == "KNP001", "single object")
check(rules("[" & wl("a") & "," & np("a", "p", denyBoth) & "]") == "", "array of objects")
check(rules("""{"items":[""" & wl("a") & "]}") == "KNP001", "items without kind")
check(rules(lst(lst(wl("a")))) == "KNP001", "nested list")
check(audit(lst(wl("a"), np("a", "p", denyIn)), "f.json")[0].where == "f.json#a", "namespace where")
check(audit(lst(np("a", "p", """{"podSelector":{},"ingress":[{}]}""")), "f.json")[0].where == "f.json#a/p", "policy where")
check(audit(lst("""{"kind":"NetworkPolicy","spec":{"podSelector":{},"ingress":[{}]}}"""), "f")[0].where == "f#default/(unnamed)", "unnamed policy")

# KNP000
check(rules("") == "KNP000", "empty")
check(rules("{nope") == "KNP000", "invalid json")
check(rules("[]") == "KNP000", "empty array")
check(rules("42") == "KNP000", "number root")
check(rules("null") == "KNP000", "null root")
check(rules("""{"a":1}""") == "KNP000", "unrelated object")
check(rules("""{"kind":"ConfigMap"}""") == "KNP000" or rules("""{"kind":"ConfigMap"}""") == "", "other kind survives")
check(audit("", "e")[0].sev == "info", "KNP000 is info")

# wrong types
check(rules("""{"kind":"List","items":[1,null,"a",[],{"kind":5}]}""") == "KNP000" or rules("""{"kind":"List","items":[1,null,"a",[],{"kind":5}]}""") == "", "wrong item types")
check(rules(lst("""{"kind":"NetworkPolicy","metadata":5,"spec":"x"}""")) == "KNP003", "bad metadata and spec types")
check(rules(lst("""{"kind":"NetworkPolicy","metadata":{"namespace":"a"},"spec":{"ingress":"x","egress":5,"podSelector":3,"policyTypes":"x"}}""")) == "KNP002,KNP003", "bad spec field types")
check(rules(lst("""{"kind":"NetworkPolicy","spec":{"ingress":[1,null,"a"],"egress":[2]}}""")) == "KNP002,KNP003", "non-object rules")

# sorting
let unsorted = @[Finding(sev: "low", rule: "B", file: "a", where: "a"), Finding(sev: "high", rule: "A", file: "z", where: "z"), Finding(sev: "high", rule: "A", file: "a", where: "a"), Finding(sev: "critical", rule: "Z", file: "z", where: "z")]
check(sortFindings(unsorted).mapIt(it.sev & it.file).join(" ") == "criticalz higha highz lowa", "sort order")
check(rank("critical") < rank("high") and rank("low") < rank("info"), "rank order")

# deep nesting
check(rules("[".repeat(5000) & "]".repeat(5000)) == "KNP000", "deeply nested JSON")
check(rules("{\"a\":".repeat(5000) & "1" & "}".repeat(5000)) == "KNP000", "deeply nested objects")

# fuzz
randomize(7)
let bits = @["{", "}", "[", "]", ",", ":", "\"kind\"", "\"NetworkPolicy\"", "\"spec\"", "\"ingress\"", "\"egress\"", "\"from\"", "\"to\"", "\"ipBlock\"", "\"cidr\"", "\"0.0.0.0/0\"", "\"items\"", "\"Deployment\"", "1", "null", "true", "\"podSelector\"", "\"policyTypes\""]
var crashed = false
for i in 1 .. 3000:
  var s = ""
  for j in 1 .. rand(1 .. 40): s.add bits[rand(bits.high)]
  try: discard audit(s, "f.json")
  except CatchableError: crashed = true
let valid = lst(wl("a"), np("a", "p", denyEg))
for i in 0 .. valid.len:
  try: discard audit(valid[0 ..< i], "f.json")
  except CatchableError: crashed = true
check(not crashed, "random and truncated inputs do not raise")

echo passed, " passed, ", failed, " failed"
quit(if failed == 0: 0 else: 1)
