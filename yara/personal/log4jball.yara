rule log4jball {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J balls"
  strings:
    $ballsrc = "NOTPOSSIBLE"
    $ballbin = "NOTPOSSIBLE"
    $balljar = "META-INF/log4j-provider.xml"
  condition:
    $ballsrc or $ballbin or $balljar
}
