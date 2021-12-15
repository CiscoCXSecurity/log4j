rule log4jball {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J balls"
    version = "1.1"
    creation_date = "2021-12-12"
    modification_date = "2021-12-15"
    classification = "TLP:WHITE"
  strings:
    $ballsrc = "PLACEHOLDER-STRING-TARBALL-MATCHES-NOT-POSSIBLE"
    $ballbin = "PLACEHOLDER-STRING-TARBALL-MATCHES-NOT-POSSIBLE"
    $balljar = "META-INF/log4j-provider.xml"
  condition:
    $ballsrc or $ballbin or $balljar
}
