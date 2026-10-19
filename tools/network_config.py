#!/usr/bin/env python3
"""Validate, sign, and verify public Drakora client configuration."""

import argparse
import base64
import ipaddress
import json
import pathlib
import re
import subprocess
import tempfile
import urllib.parse

MAX_BYTES = 256 * 1024
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})")
DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def document(data):
    require(len(data) <= MAX_BYTES, "Configuration exceeds size limit")
    result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Invalid JSON number")))
    structure(result, 0, [4096])
    return result


def structure(value, depth, remaining):
    remaining[0] -= 1
    require(depth <= 24 and remaining[0] >= 0, "JSON structure exceeds limits")
    if isinstance(value, dict):
        for key, item in value.items():
            require(len(key.encode("utf-16-le")) // 2 <= 128, "JSON key exceeds limit")
            structure(item, depth + 1, remaining)
    elif isinstance(value, list):
        for item in value:
            structure(item, depth + 1, remaining)
    elif isinstance(value, str):
        require(len(value.encode("utf-16-le")) // 2 <= 192 * 1024, "JSON string exceeds limit")
    elif type(value) in (int, float):
        require(len(str(value)) <= 32, "JSON number exceeds limit")


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, "Integer outside allowed range")
    return value


def domain(value):
    require(isinstance(value, str) and len(value) <= 253 and DOMAIN.fullmatch(value.lower())
            and not re.fullmatch(r"[0-9.]+", value), "Invalid public domain")
    return value.lower()


def https(value):
    require(isinstance(value, str) and len(value) <= 2048, "Invalid HTTPS URL")
    uri = urllib.parse.urlsplit(value)
    require(uri.scheme == "https" and uri.hostname and uri.port is None and uri.username is None
            and uri.password is None and not uri.query and not uri.fragment and "/../" not in uri.path
            and "/./" not in uri.path, "Expected a public HTTPS URL")
    domain(uri.hostname)
    return uri


def sequence(root, name, maximum, empty=False):
    values = root.get(name)
    require(isinstance(values, list) and (empty or len(values) > 0) and len(values) <= maximum,
            "Invalid " + name)
    return values


def validate(root):
    require(isinstance(root, dict), "Expected configuration object")
    integer(root.get("schemaVersion"), 1, 1)
    integer(root.get("revision"), 1, 9223372036854775807)
    domains = [domain(value) for value in sequence(root, "domains", 32)]
    require(len(set(domains)) == len(domains), "Duplicate network domain")
    addresses = set()
    for value in sequence(root, "addresses", 128):
        require(isinstance(value, dict), "Invalid network endpoint")
        host = str(ipaddress.ip_address(value["host"]))
        require(host not in addresses, "Duplicate network address")
        addresses.add(host)
        ports = sequence(value, "ports", 32)
        for port in ports:
            integer(port, 1, 65535)
        require(len(set(ports)) == len(ports), "Duplicate endpoint port")
    for value in sequence(root, "configurationSources", 4):
        https(value)
    downloads = [https(value) for value in sequence(root, "downloadRoots", 8)]
    require(all(uri.path.endswith("/") and "%" not in uri.path for uri in downloads), "Invalid download root")
    if "downloadRedirectHosts" in root:
        for value in sequence(root, "downloadRedirectHosts", 8):
            domain(value)
    project = https(root["curseforgeProject"])
    require(project.hostname == "www.curseforge.com" and re.fullmatch(r"/minecraft/mc-mods/[a-z0-9-]+", project.path),
            "Invalid CurseForge project")
    for release in sequence(root, "releases", 128, empty=True):
        require(isinstance(release, dict), "Invalid release")
        require(release.get("loader") in ("forge", "fabric") and release.get("minecraft") == "1.20.1", "Unsupported release target")
        version = release.get("version")
        require(isinstance(version, str) and VERSION.fullmatch(version), "Invalid release version")
        prefix = "PVelocity-RH-Patch-" if release["loader"] == "forge" else "PVelocity-Prom2-Patch-"
        require(release.get("fileName") == prefix + version + ".jar", "Wrong release filename")
        integer(release.get("size"), 1, 8 * 1024 * 1024)
        integer(release.get("build", 0), 0, 9223372036854775807)
        require(isinstance(release.get("sha256"), str) and re.fullmatch(r"[a-fA-F0-9]{64}", release["sha256"]), "Invalid checksum")
        uri = https(release["downloadUrl"])
        allowed = False
        for root_uri in downloads:
            if uri.hostname == root_uri.hostname and uri.path.startswith(root_uri.path) and "%" not in uri.path:
                suffix = uri.path[len(root_uri.path):].split("/")
                allowed |= (len(suffix) == 2 and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", suffix[0])
                            and suffix[0] not in (".", "..") and suffix[1] == release["fileName"])
        require(allowed, "Release download is outside signed download roots")
        uri = https(release["curseforgeUrl"])
        require(uri.hostname == project.hostname and re.fullmatch(re.escape(project.path) + r"/files/[1-9][0-9]*", uri.path),
                "Release must link to the selected CurseForge project")
    return root


def verify(root):
    payload = (root / "network.json").read_bytes()
    require(len(payload) <= 128 * 1024, "Signed payload exceeds size limit")
    validate(document(payload))
    envelope = document((root / "network.signed.json").read_bytes())
    integer(envelope.get("schemaVersion"), 1, 1)
    require(base64.b64decode(envelope["payload"], validate=True) == payload, "Signed payload differs from network.json")
    signature = base64.b64decode(envelope["signature"], validate=True)
    require(len(signature) == 64, "Invalid Ed25519 signature size")
    with tempfile.TemporaryDirectory(prefix="drakora-config-verify-") as temporary:
        path = pathlib.Path(temporary)
        (path / "payload").write_bytes(payload)
        (path / "signature").write_bytes(signature)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey",
                        str(root / "network-config.pub"), "-rawin", "-in", str(path / "payload"),
                        "-sigfile", str(path / "signature")], check=True, capture_output=True)
    expected = {"schemaVersion": 1, "releases": document(payload)["releases"]}
    require(document((root / "updates.json").read_bytes()) == expected, "Legacy feed does not match the signed release catalog")


def sign(root, key):
    require(key.is_file() and not key.is_symlink() and key.stat().st_mode & 0o077 == 0,
            "Signing key must be a private file")
    require(not key.resolve().is_relative_to(root.resolve()), "Keep the private signing key outside this repository")
    payload = (root / "network.json").read_bytes()
    require(len(payload) <= 128 * 1024, "Signed payload exceeds size limit")
    config = validate(document(payload))
    public = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"],
                            check=True, capture_output=True).stdout
    require(public == (root / "network-config.pub").read_bytes(), "Signing key does not match the client trust key")
    signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key),
                                "-in", str(root / "network.json")], check=True, capture_output=True).stdout
    envelope = {"schemaVersion": 1, "payload": base64.b64encode(payload).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii")}
    (root / "network.signed.json").write_text(json.dumps(envelope, indent=2) + "\n")
    (root / "updates.json").write_text(json.dumps({"schemaVersion": 1, "releases": config["releases"]}, indent=2) + "\n")
    verify(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify", "sign"))
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--key", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.command == "sign":
        require(arguments.key is not None, "Signing requires --key")
        sign(arguments.root, arguments.key)
    else:
        verify(arguments.root)
    print("Configuration signature and release catalog verified.")


if __name__ == "__main__":
    main()
