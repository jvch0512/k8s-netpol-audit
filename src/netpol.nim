import std/[json, algorithm, strutils, tables, sets, os]

type
  Finding* = object
    sev*, rule*, file*, where*, msg*: string

proc rank*(sev: string): int =
  case sev
  of "critical": 0
  of "high": 1
  of "medium": 2
  of "low": 3
  else: 4

const
  WorkloadKinds = ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod", "ReplicationController"]
  SystemNs = ["kube-system", "kube-public", "kube-node-lease"]

proc info(file, msg: string): seq[Finding] =
  @[Finding(sev: "info", rule: "KNP000", file: file, where: file, msg: msg)]

proc maxDepth(s: string): int =
  ## deepest bracket nesting outside strings, used to refuse hostile input
  var d = 0
  var inStr = false
  var esc = false
  for c in s:
    if inStr:
      if esc: esc = false
      elif c == '\\': esc = true
      elif c == '"': inStr = false
    else:
      case c
      of '"': inStr = true
      of '[', '{':
        inc d
        if d > result: result = d
      of ']', '}': dec d
      else: discard

proc jstr(n: JsonNode, key: string): string =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JString: n[key].getStr().strip() else: ""

proc jarr(n: JsonNode, key: string): seq[JsonNode] =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JArray: n[key].elems else: @[]

proc jobj(n: JsonNode, key: string): JsonNode =
  if n.kind == JObject and n.hasKey(key) and n[key].kind == JObject: n[key] else: newJObject()

proc collect(n: JsonNode, acc: var seq[JsonNode], depth = 0) =
  if depth > 8: return
  if n.kind == JArray:
    for x in n.elems: collect(x, acc, depth + 1)
  elif n.kind == JObject:
    if n.hasKey("items") and n["items"].kind == JArray:
      for x in n["items"].elems: collect(x, acc, depth + 1)
    elif n.hasKey("kind") and n["kind"].kind == JString:
      acc.add n

proc nsOf(o: JsonNode): string =
  let m = o.jobj("metadata")
  let ns = m.jstr("namespace")
  if ns == "": "default" else: ns

proc hasType(spec: JsonNode, t: string): bool =
  for x in spec.jarr("policyTypes"):
    if x.kind == JString and x.getStr() == t: return true

proc audit*(text, file: string): seq[Finding] =
  if text.len > 0 and maxDepth(text) > 200:
    return info(file, "not valid JSON, ignored")
  var root: JsonNode
  try:
    root = parseJson(text)
  except CatchableError:
    return info(file, "not valid JSON, ignored")
  var objs: seq[JsonNode]
  collect(root, objs)
  if objs.len == 0:
    return info(file, "no Kubernetes objects found, ignored")
  var workloads = initOrderedSet[string]()
  var policies = initTable[string, seq[JsonNode]]()
  var nsOrder: seq[string]
  var known = initHashSet[string]()
  proc see(ns: string) =
    if ns notin known:
      known.incl ns
      nsOrder.add ns
  for o in objs:
    let kind = o.jstr("kind")
    if kind == "NetworkPolicy":
      let ns = nsOf(o)
      see ns
      policies.mgetOrPut(ns, @[]).add o
    elif kind in WorkloadKinds:
      let ns = nsOf(o)
      see ns
      workloads.incl ns
  var denyIn = initHashSet[string]()
  var denyEg = initHashSet[string]()
  for ns in nsOrder:
    for p in policies.getOrDefault(ns):
      let name = block:
        let n = p.jobj("metadata").jstr("name")
        if n == "": "(unnamed)" else: n
      let where = file & "#" & ns & "/" & name
      let spec = p.jobj("spec")
      let sel = spec.jobj("podSelector")
      let emptySel = sel.len == 0 or (sel.kind == JObject and sel.len == 0)
      let selAll = emptySel or (sel.hasKey("matchLabels") and sel["matchLabels"].len == 0 and not sel.hasKey("matchExpressions"))
      let ingressRules = spec.jarr("ingress")
      let egressRules = spec.jarr("egress")
      let types = spec.jarr("policyTypes")
      let ingActive = spec.hasType("Ingress") or (types.len == 0)
      if selAll and ingActive and ingressRules.len == 0 and not spec.hasKey("ingress"):
        denyIn.incl ns
      if selAll and spec.hasType("Egress") and egressRules.len == 0 and not spec.hasKey("egress"):
        denyEg.incl ns
      for r in ingressRules:
        if r.kind != JObject: continue
        let fr = r.jarr("from")
        if not r.hasKey("from") or (r["from"].kind == JArray and fr.len == 0):
          result.add Finding(sev: "medium", rule: "KNP005", file: file, where: where, msg: name & " has an ingress rule with no `from`, every source is allowed")
        for f in fr:
          let b = f.jobj("ipBlock")
          let cidr = b.jstr("cidr")
          if cidr == "0.0.0.0/0" or cidr == "::/0":
            result.add Finding(sev: "high", rule: "KNP004", file: file, where: where, msg: name & " allows ingress from " & cidr)
      for r in egressRules:
        if r.kind != JObject: continue
        if not r.hasKey("to") or (r["to"].kind == JArray and r["to"].elems.len == 0):
          result.add Finding(sev: "low", rule: "KNP006", file: file, where: where, msg: name & " has an egress rule with no `to`, every destination is allowed")
  for ns in nsOrder:
    if ns in SystemNs: continue
    let w = file & "#" & ns
    if ns in workloads and not policies.hasKey(ns):
      result.add Finding(sev: "high", rule: "KNP001", file: file, where: w, msg: "namespace " & ns & " runs workloads and has no NetworkPolicy")
    elif policies.hasKey(ns):
      if ns notin denyIn:
        result.add Finding(sev: "medium", rule: "KNP002", file: file, where: w, msg: "namespace " & ns & " has no default-deny ingress policy")
      if ns notin denyEg:
        result.add Finding(sev: "low", rule: "KNP003", file: file, where: w, msg: "namespace " & ns & " has no default-deny egress policy")

proc cmpFinding(a, b: Finding): int =
  result = cmp(rank(a.sev), rank(b.sev))
  if result == 0: result = cmp(a.file, b.file)
  if result == 0: result = cmp(a.rule, b.rule)
  if result == 0: result = cmp(a.where, b.where)

proc sortFindings*(f: seq[Finding]): seq[Finding] =
  result = f
  result.sort(cmpFinding)

proc walk(dir, root: string, depth: int, acc: var seq[(string, string)]) =
  if depth > 30: return
  var files: seq[string]
  var dirs: seq[string]
  try:
    for kind, p in walkDir(dir):
      if kind == pcFile and p.endsWith(".json"): files.add p
      elif kind == pcDir and extractFilename(p) != ".git": dirs.add p
  except OSError:
    return
  files.sort()
  dirs.sort()
  for f in files: acc.add((relativePath(f, root).replace('\\', '/'), f))
  for d in dirs: walk(d, root, depth + 1, acc)

proc auditPath*(path: string, fileCount: var int): seq[Finding] =
  var files: seq[(string, string)]
  if dirExists(path): walk(path, path, 0, files)
  else: files.add((extractFilename(path), path))
  fileCount = files.len
  var all: seq[Finding]
  for (rel, full) in files:
    var text = ""
    try:
      if getFileSize(full) <= 50_000_000: text = readFile(full)
    except CatchableError:
      discard
    all.add audit(text, rel)
  result = sortFindings(all)
