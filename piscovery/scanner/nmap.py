import asyncio
import shlex
import shutil
import xml.etree.ElementTree as ET

from ..core.models import NmapResult


def is_available() -> str:
    return shutil.which("nmap") or ""


async def run_nmap(target: str, extra_args: str = "", timeout: int = 300) -> NmapResult:
    cmd = ["nmap", "-sV", "-T4", "--open", "-oX", "-"]
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    cmd.append(target)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return NmapResult(raw_output="[nmap timed out]")

    raw = stdout.decode("utf-8", errors="replace")
    result = NmapResult(raw_output=raw)
    _parse_xml(raw, result)
    return result


def _parse_xml(xml_str: str, result: NmapResult) -> None:
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return

    for host in root.findall(".//host"):
        os_el = host.find(".//osmatch")
        if os_el is not None:
            result.os_detection = os_el.get("name", "")

        for port_el in host.findall(".//port"):
            proto = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "")
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_str = f"{portid}/{proto}"
            result.open_ports.append(port_str)

            svc_el = port_el.find("service")
            if svc_el is None:
                result.services[port_str] = "unknown"
                continue

            svc_name = svc_el.get("name", "unknown")
            svc_product = svc_el.get("product", "")
            svc_version = svc_el.get("version", "")
            svc_info = svc_name
            if svc_product:
                svc_info += f" ({svc_product}"
                if svc_version:
                    svc_info += f" {svc_version}"
                svc_info += ")"
            result.services[port_str] = svc_info
