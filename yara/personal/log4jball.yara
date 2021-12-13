rule log4jball {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J balls"
  strings:
    $ballsrc = "PLACEHOLDER-STRING-TARBALL-MATCHES-NOT-POSSIBLE"
    $ballbin = "PLACEHOLDER-STRING-TARBALL-MATCHES-NOT-POSSIBLE"
    $balljar = "META-INF/log4j-provider.xml"
  condition:
    $ballsrc or $ballbin or $balljar
}
