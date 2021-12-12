rule log4jjavasrc {
  meta:
    author = "Tim Brown @timb_machine"
    description = "Hunts for references to Log4J java in source form"
  strings:
    $javasrc = "org.apache.logging.log4j"
  condition:
    $javasrc
}
