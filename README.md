# Introduction
This Nagios-like plugin can be used to check the average traffic on Linux systems.
It keeps track of the amount of bytes sent and received per interface with a state file.
It supports thresholds and filters.

# Requirements

The script requires:
* Python 3.7 or newer
* [`nagiosplugin`](https://nagiosplugin.readthedocs.io) version 1.2.4 or newer
* iproute2 4.14.0 or newer
* read-write access to `/tmp/` (where the state file is stored)

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
    "--warning" = "$traffic_warning$",
    "--critical" = "$traffic_critical$",
  }
}
```
