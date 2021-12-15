rule log4jjavasrc {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J java in source form"
    version = "1.0"
    creation_date = "2021-12-12"
    modification_date = "2021-12-15"
    classification = "TLP:WHITE"
  strings:
    $javasrc = "org.apache.logging.log4j"
  condition:
    $javasrc
}
