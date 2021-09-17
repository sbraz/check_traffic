#!/usr/bin/env python3
"""Nagios-like plugin to check traffic per interface"""

import argparse
import hashlib
import json
import logging
import pathlib
import pickle
import re
import subprocess
import time

import nagiosplugin  # type: ignore

logger = logging.getLogger("nagiosplugin")

CHECK_NAME = pathlib.Path(__file__).name
STATE_FILE_PATH = "/tmp"


def prettify_size(size, multiplier):
    binary_str = "i" if multiplier == 1024 else ""
    for unit in ("", f"K{binary_str}", f"M{binary_str}", f"G{binary_str}"):
        if abs(size) < multiplier:
            return f"{size:.1f}{unit}"
        size /= multiplier
    return f"{size:.1f}T{binary_str}"


def human_size(string):
    match = re.search(r"\A(\d+)([KMGT]?)\Z", string, flags=re.I)
    if not match:
        raise argparse.ArgumentTypeError(
            f"invalid argument: {string}, must be an integer, "
            "optionally followed by K, M, G or T (case-insensitive)"
        )
    value, unit = match.groups()
    units = ("", "K", "M", "G", "T")
    power = units.index(unit.upper())
    return int(value), power


class Traffic(nagiosplugin.Resource):
    def __init__(self, args, args_hash):
        self.args = args
        self.args_hash = args_hash
        self.old_state = {}
        self.current_state = {"statistics": {}}

    @classmethod
    def _get_interfaces(cls):
        command = ["ip", "-details", "-statistics", "-json", "link", "show"]
        try:
            proc = subprocess.run(
                command,
                check=True,
                text=True,
                capture_output=True,
            )
            execution_time = time.time()
        except subprocess.CalledProcessError as exc:
            raise nagiosplugin.CheckError(
                f"command {command} exited with status {exc.returncode}: {exc.stderr!r}"
            )
        logger.debug("Output from %s: %s", " ".join(command), proc.stdout)
        return execution_time, json.loads(proc.stdout)

    def _include_interface(self, interface):
        interface_name = interface["ifname"]
        interface_type = interface["link_type"]
        if "linkinfo" in interface and "info_kind" in interface["linkinfo"]:
            interface_type = interface["linkinfo"]["info_kind"]
        interface["computed_type"] = interface_type
        # Exclude interfaces which are down
        if not self.args.down and interface["operstate"] == "DOWN":
            logger.info(
                "[-] Skipping interface %s (operstate DOWN)",
                interface_name,
            )
            return False
        # Exclusions first
        if interface_type in self.args.exclude_type:
            logger.info(
                "[-] Skipping interface %s (type %s matches %s)",
                interface_name,
                interface_type,
                self.args.exclude_type,
            )
            return False
        if self.args.exclude_name and re.search(self.args.exclude_name, interface_name):
            logger.info(
                "[-] Skipping interface %s (name matches %s)",
                interface_name,
                self.args.exclude_name,
            )
            return False
        # Then inclusions, if any
        inclusion_tests = []
        if self.args.type:
            inclusion_tests.append(("type", self.args.type, interface_type in self.args.type))
        if self.args.name:
            inclusion_tests.append(
                ("name", self.args.name, re.search(self.args.name, interface_name))
            )
        if inclusion_tests:
            messages = []
            tests_match = True
            for test_type, test_str, test_result in inclusion_tests:
                verb = "matches" if test_result else "does not match"
                additional_info = f" {interface_type}" if test_type == "type" else ""
                messages.append(f"{test_type}{additional_info} {verb} {test_str}")
                # We must match all conditions
                tests_match = tests_match and test_result
            logger.info(
                "%s interface %s (%s)",
                "[+] Including" if tests_match else "[-] Skipping",
                interface_name,
                ", ".join(messages),
            )
            return tests_match
        # If there are no inclusions, implicitly include the interface
        logger.info(
            "[+] Including interface %s of type %s (no inclusion filter specified)",
            interface_name,
            interface_type,
        )
        return True

    def _load_cookie(self, state_file):
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            self.old_state = cookie
            if self.old_state:
                logger.debug("Loaded old metrics from %s", state_file)
            else:
                yield nagiosplugin.Metric(
                    name="Warn",
                    value={"message": f"no data in state file {state_file}, first run?"},
                    context="metadata",
                )

    @classmethod
    def _save_cookie(cls, state_file, state):
        with nagiosplugin.Cookie(str(state_file)) as cookie:
            # We can't just copy the dict to the cookie
            for key, value in state.items():
                cookie[key] = value

    def _probe_interface(self, interface):
        interface_name = interface["ifname"]
        self.current_state["statistics"][interface_name] = {}
        for direction in ("rx", "tx"):
            self.current_state["statistics"][interface_name][direction] = interface["stats64"][
                direction
            ]["bytes"]
        # Two cases where we can't compute the bandwidth:
        # 1. no old data, e.g. first run
        if not self.old_state:
            return
        # 2. new interface
        if self.old_state and interface_name not in self.old_state["statistics"]:
            yield nagiosplugin.Metric(
                name="Warn",
                value={"message": f"no data in state file for {interface_name}, new interface?"},
                context="metadata",
            )
            return
        time_delta = self.current_state["execution_time"] - self.old_state["execution_time"]
        if self.args.bytes:
            unit = "B"
            multiplier = 1
        else:
            unit = "b"
            multiplier = 8
        for direction, current_bytes in self.current_state["statistics"][interface_name].items():
            bandwidth = (
                multiplier
                * (current_bytes - self.old_state["statistics"][interface_name][direction])
                / time_delta
            )
            if bandwidth < 0:
                yield nagiosplugin.Metric(
                    name="Warn",
                    value={
                        "message": f"Counter for {interface_name}/{direction} is decreasing,"
                        " this could be caused by a reboot"
                    },
                    context="metadata",
                )
                return
            yield nagiosplugin.Metric(
                name=f"{interface_name}_{direction}", value=bandwidth, uom=unit, context=direction
            )

    def probe(self):
        state_file = pathlib.Path(STATE_FILE_PATH) / f".{CHECK_NAME}_{self.args_hash}"
        yield from self._load_cookie(state_file)
        execution_time, interfaces = self._get_interfaces()
        if not interfaces:
            raise nagiosplugin.CheckError("No interfaces found")
        filtered_interfaces = [e for e in interfaces if self._include_interface(e)]
        logger.info("Included interfaces: %s", ", ".join(e["ifname"] for e in filtered_interfaces))
        if not filtered_interfaces:
            raise nagiosplugin.CheckError("No matching interfaces found after applying filters")
        self.current_state["execution_time"] = execution_time
        for interface in filtered_interfaces:
            yield from self._probe_interface(interface)
        self._save_cookie(state_file, self.current_state)


class MetadataContext(nagiosplugin.Context):
    def evaluate(self, metric, resource):
        state_cls = getattr(nagiosplugin.state, metric.name)
        return self.result_cls(state=state_cls, hint=metric.value["message"], metric=metric)


# No traceback display during argument parsing
@nagiosplugin.guarded(verbose=0)
def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter, description=__doc__
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="enable more verbose output, can be specified multiple times",
        default=0,
        action="count",
    )
    filter_group = parser.add_argument_group(
        "filtering options, exclusions are applied before inclusions, "
        "increase verbosity for details"
    )
    filter_group.add_argument(
        "-t",
        "--type",
        help="only select interfaces of this type, can be specified multiple times",
        action="append",
        default=[],
    )
    filter_group.add_argument(
        "-T",
        "--exclude-type",
        help="exclude interfaces of this type, can be specified multiple times",
        action="append",
        default=[],
    )
    filter_group.add_argument(
        "-n", "--name", help="only select interfaces whose name matches this regex"
    )
    filter_group.add_argument(
        "-N", "--exclude-name", help="exclude interfaces whose name matches this regex"
    )
    filter_group.add_argument(
        "-d",
        "--down",
        help="include interfaces whose operstate is down",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-b",
        "--bytes",
        help="use bytes as output unit instead of bits, does not affect thresholds",
        action="store_true",
        default=False,
    )
    threshold_group = parser.add_argument_group(
        "threshold options, suffixes K, M, G and T (case-insensitive) are accepted, "
        "multiples of 1000 are used for bits and 1024 for bytes"
    )
    threshold_group.add_argument(
        "-w",
        "--warning",
        metavar=("RX", "TX"),
        nargs=2,
        help="warning threshold",
        type=human_size,
    )
    threshold_group.add_argument(
        "-c",
        "--critical",
        metavar=("RX", "TX"),
        nargs=2,
        help="critical threshold",
        type=human_size,
    )
    args = parser.parse_args()
    multiplier = 1024 if args.bytes else 1000
    for threshold in ("warning", "critical"):
        arg = getattr(args, threshold)
        for i, direction in enumerate(("rx", "tx")):
            setattr(args, f"{threshold}_{direction}", None)
            if arg:
                setattr(
                    args,
                    f"{threshold}_{direction}",
                    arg[i][0] * multiplier ** arg[i][1],
                )
    return args


class TrafficSummary(nagiosplugin.Summary):
    def ok(self, results):
        return ""

    def verbose(self, results):
        messages = []
        for result in results:
            if not result.context or result.context.name not in ("rx", "tx"):
                continue
            human_readable_value = prettify_size(
                result.metric.value, 1024 if result.metric.uom == "B" else 1000
            )
            messages.append(f"{result.metric.name} = {human_readable_value}{result.metric.uom}/s")
        return "\n".join(messages)

    def problem(self, results):
        messages = []
        # Worst results first
        for result in sorted(results, key=lambda x: x.state, reverse=True):
            if result.state == nagiosplugin.state.Ok:
                continue
            if result.context and result.context.name in ("rx", "tx"):
                human_readable_value = prettify_size(
                    result.metric.value, 1024 if result.metric.uom == "B" else 1000
                )
                messages.append(
                    f"{result.metric.name} ="
                    f" {human_readable_value}{result.metric.uom}/s ({result.hint})"
                )
            else:
                messages.append(result.hint)
        return ", ".join(messages)


@nagiosplugin.guarded
def main(args):
    # Unique identifier used to store check state
    relevant_args = []
    for arg, arg_val in sorted(vars(args).items()):
        if arg not in ("verbose",):
            relevant_args.append((arg, arg_val))
    args_hash = hashlib.sha1(pickle.dumps(relevant_args)).hexdigest()
    check = nagiosplugin.Check(
        Traffic(args, args_hash),
        MetadataContext("metadata"),
        nagiosplugin.ScalarContext("rx", args.warning_rx, args.critical_rx),
        nagiosplugin.ScalarContext("tx", args.warning_tx, args.critical_tx),
        TrafficSummary(),
    )
    check.main(args.verbose)


if __name__ == "__main__":
    main(parse_args())
