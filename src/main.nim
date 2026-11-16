import std/[os, strutils]
import netpol

proc usage(): int =
  stderr.writeLine "usage: k8s-netpol-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."
  2

proc run(): int =
  var path = ""
  var havePath = false
  var tsv = false
  var failOn = ""
  let args = commandLineParams()
  var i = 0
  while i < args.len:
    let a = args[i]
    if a == "--tsv": tsv = true
    elif a == "--fail-on":
      inc i
      if i >= args.len or args[i] notin ["medium", "high", "critical"]: return usage()
      failOn = args[i]
    elif a.startsWith("-") and a.len > 1: return usage()
    elif havePath: return usage()
    else:
      path = a
      havePath = true
    inc i
  if not havePath: return usage()
  if not (fileExists(path) or dirExists(path)):
    stderr.writeLine "error: no such file or directory: " & path
    return 2
  var p = path
  if p.len > 1: p = p.strip(leading = false, chars = {'/'})
  if p == "": p = "/"
  var n = 0
  let fs = auditPath(p, n)
  var o = ""
  let head = $n & " files, " & $fs.len & " findings"
  o.add (if tsv: "# " & head else: head) & "\n"
  for f in fs:
    if tsv:
      o.add f.sev & "\t" & f.rule & "\t" & f.where & "\t" & f.msg & "\n"
    else:
      o.add f.sev.toUpperAscii().alignLeft(8) & " " & f.rule & " " & f.where & "\n"
      o.add "         " & f.msg & "\n"
  stdout.write o
  if failOn != "":
    for f in fs:
      if rank(f.sev) <= rank(failOn): return 1
  0

quit run()
