"""Fetch the pinned Geist Sans asset once; no package scripts are executed."""
import base64
import hashlib
import io
import http.client
import json
from pathlib import Path
import tarfile

VERSION = "1.9.2"
REGISTRY = "https://registry.npmjs.org/geist"
ARCHIVE = f"{REGISTRY}/-/geist-{VERSION}.tgz"
FONT = "package/dist/fonts/geist-sans/Geist-Variable.woff2"
LICENSES = ("package/LICENSE.txt", "package/LICENSE", "package/OFL.txt", "package/license.txt")
STATIC = Path(__file__).resolve().parents[1] / "domain_guard/static"

def download(url, limit):
    if(not url.startswith(REGISTRY + "/")):
        raise ValueError("Unexpected registry URL")
    connection = http.client.HTTPSConnection("registry.npmjs.org", timeout=30)
    try:
        connection.request("GET", url.removeprefix("https://registry.npmjs.org"))
        with connection.getresponse() as response:
            if(response.status != 200):
                raise ValueError(f"Registry returned HTTP {response.status}")
            data = response.read(limit + 1)
    finally:
        connection.close()
    if(len(data) > limit):
        raise ValueError("Registry response exceeds size limit")
    return data

def get_member(archive, name, limit):
    member = archive.getmember(name)
    if(not member.isfile() or member.size > limit):
        raise ValueError("Invalid package member")
    with archive.extractfile(member) as stream:
        return stream.read(limit + 1)

def extract_assets(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        font = get_member(archive, FONT, 2 * 1024 * 1024)
        names = set(archive.getnames())
        license_name = next((name for name in LICENSES if name in names), None)
        if(license_name is None):
            raise ValueError("Font license not found in package")
        license_text = get_member(archive, license_name, 64 * 1024)
    if(not font.startswith(b"wOF2") or b"SIL OPEN FONT LICENSE" not in license_text.upper()):
        raise ValueError("Unexpected font or license format")
    return font, license_text

def main():
    meta = json.loads(download(f"{REGISTRY}/{VERSION}", 1024 * 1024))
    if(meta["name"] != "geist" or meta["version"] != VERSION or meta["dist"]["tarball"] != ARCHIVE):
        raise ValueError("Unexpected registry metadata")
    data = download(ARCHIVE, 64 * 1024 * 1024)
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    if(integrity not in meta["dist"]["integrity"].split()):
        raise ValueError("Package integrity mismatch")
    font, license_text = extract_assets(data)
    (STATIC / "Geist-LICENSE.txt").write_bytes(license_text)
    (STATIC / "Geist-Variable.woff2").write_bytes(font)
    print(f"Geist {VERSION} installed in {STATIC}")

if(__name__ == "__main__"):
    main()
