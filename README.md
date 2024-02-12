# Introduction
This Nagios-like plugin can be used to check the average traffic on Linux systems.
It keeps track of the amount of bytes sent and received per interface with a state file.
It supports thresholds and filters. The `-v/--verbose` option can help debug
what inclusion/exclusion rules are matched.

# Requirements

The script requires:
* Python 3.7 or newer
* [`nagiosplugin`](https://nagiosplugin.readthedocs.io) version 1.2.4 or newer
* iproute2 4.14.0 or newer
* read-write access to `/tmp/` (where the state file is stored)
* sudo if `--include-netns` is used

# Integration with Icinga

An Icinga `CheckCommand` can be defined with:
```
object CheckCommand "traffic" {
  command = [PluginDir + "/check_traffic.py"]
  arguments = {
    "--type" = "$traffic_interface_type$",
    "--name" = "$traffic_interface_name$",
    "--exclude-type" = "$traffic_interface_exclude_type$",
    "--exclude-name" = "$traffic_interface_exclude_name$",
    "--down" = {
      set_if = "$traffic_include_down_interfaces$"
    },
    "--bytes" = {
      set_if = "$traffic_use_bytes$"
    },
    "--include-netns" = {
      set_if = "$traffic_include_netns$"
    },
    "--warning" = "$traffic_warning$",
    "--critical" = "$traffic_critical$",
  }
}
```

# Example sudoers configuration

Starting with sudo 1.9.10, it is possible to use regular expressions in sudoers
files. The following example `/etc/sudoers.d/icinga2-check-traffic` file takes
advantage of this feature. It will allow the check to work with network
namespaces whose names are made up of simple alphanumeric characters and
underscores, while minimizing the risk of injection.
```
icinga ALL=(ALL) NOPASSWD: /bin/ip ^-netns [a-zA-Z0-9_]+ -details -statistics -json link show$
```
