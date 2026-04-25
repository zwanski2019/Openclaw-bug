"""Recon tool plugins. Each wraps a binary with safe arg construction."""
from __future__ import annotations
from openclaw.tools.registry import Tool, register_tool


@register_tool
class Subfinder(Tool):
    name = "subfinder"
    binary = "subfinder"
    description = "Passive subdomain enumeration (ProjectDiscovery)"

    def build_args(self, target: str, **kwargs) -> list[str]:
        args = ["-d", target, "-silent", "-all"]
        if kwargs.get("recursive"):
            args.append("-recursive")
        return args


@register_tool
class Assetfinder(Tool):
    name = "assetfinder"
    binary = "assetfinder"
    description = "Quick passive subdomain enum (tomnomnom)"

    def build_args(self, target: str, **kwargs) -> list[str]:
        return ["--subs-only", target]


@register_tool
class HttpxProbe(Tool):
    name = "httpx"
    binary = "httpx"
    description = "HTTP probe with tech detection, titles, status codes"

    def build_args(self, target: str, **kwargs) -> list[str]:
        # httpx supports stdin list via `-l` — but we're running per-target here.
        # For a subs list, pass a file path and call with special handling.
        args = [
            "-u", target,
            "-silent",
            "-sc", "-title", "-tech-detect",
            "-cdn", "-jarm", "-favicon",
            "-json",
        ]
        if kwargs.get("follow_redirects"):
            args.append("-fr")
        return args


@register_tool
class HttpxList(Tool):
    """For scanning a list of hosts from file."""
    name = "httpx_list"
    binary = "httpx"
    description = "httpx probe against a list file of subdomains"
    skip_scope = True  # target is a file path, not a hostname

    def build_args(self, target: str, **kwargs) -> list[str]:
        # target is the path to a file of hosts
        return [
            "-l", target,
            "-silent", "-sc", "-title", "-tech-detect", "-cdn",
            "-json",
        ]


@register_tool
class Nuclei(Tool):
    name = "nuclei"
    binary = "nuclei"
    description = "Templated vulnerability scanner"
    default_timeout = 1800  # 30 min

    def build_args(self, target: str, **kwargs) -> list[str]:
        # -j writes JSONL to stdout; -json-export requires a file path and won't work with "-"
        args = ["-u", target, "-silent", "-j"]
        severity = kwargs.get("severity", "medium,high,critical")
        args += ["-severity", severity]
        if tags := kwargs.get("tags"):
            args += ["-tags", tags]
        if kwargs.get("automatic_scan"):
            args += ["-as"]
        return args


@register_tool
class Katana(Tool):
    name = "katana"
    binary = "katana"
    description = "JS-aware crawler"

    def build_args(self, target: str, **kwargs) -> list[str]:
        return ["-u", target, "-silent", "-jc", "-kf", "all",
                "-d", str(kwargs.get("depth", 3))]


@register_tool
class Naabu(Tool):
    name = "naabu"
    binary = "naabu"
    description = "Fast port scanner"

    def build_args(self, target: str, **kwargs) -> list[str]:
        ports = kwargs.get("ports", "top-1000")
        args = ["-host", target, "-silent", "-json"]
        if ports == "top-1000":
            args += ["-top-ports", "1000"]
        elif ports == "top-100":
            args += ["-top-ports", "100"]
        else:
            args += ["-p", ports]
        return args


@register_tool
class Nmap(Tool):
    name = "nmap"
    binary = "nmap"
    description = "Service / version detection scan"
    default_timeout = 1800

    def build_args(self, target: str, **kwargs) -> list[str]:
        # Conservative default: top 1000 TCP, service detect, no aggressive
        args = ["-sV", "-T3", "--top-ports", "1000", "-oX", "-", target]
        if kwargs.get("scripts"):
            args += ["--script", kwargs["scripts"]]
        return args


@register_tool
class Ffuf(Tool):
    name = "ffuf"
    binary = "ffuf"
    description = "Content / parameter fuzzer"
    default_timeout = 1200

    def build_args(self, target: str, **kwargs) -> list[str]:
        wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        return [
            "-u", target,
            "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403,405",
            "-fs", "0",
            "-of", "json", "-o", "-",
            "-s",
        ]


@register_tool
class Waybackurls(Tool):
    name = "waybackurls"
    binary = "waybackurls"
    description = "Historical URLs from Wayback Machine"

    def build_args(self, target: str, **kwargs) -> list[str]:
        return [target]
