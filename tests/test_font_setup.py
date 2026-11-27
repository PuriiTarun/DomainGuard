import base64
import hashlib
import io
import json
import tarfile
import pytest
from scripts import install_geist

def archive(font=b"wOF2 mock", license_text=b"SIL OPEN FONT LICENSE"):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for name, content in [(install_geist.FONT, font), (install_geist.LICENSES[0], license_text)]:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return out.getvalue()

def test_extract_pinned_assets():
    assert install_geist.extract_assets(archive()) == (b"wOF2 mock", b"SIL OPEN FONT LICENSE")

@pytest.mark.parametrize("font,license_text", [(b"invalid", b"SIL OPEN FONT LICENSE"), (b"wOF2 mock", b"invalid")])
def test_invalid_assets_rejected(font, license_text):
    with pytest.raises(ValueError):
        install_geist.extract_assets(archive(font, license_text))

def test_setup_checks_integrity_before_writing(monkeypatch, tmp_path):
    data = archive()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    meta = {"name": "geist", "version": install_geist.VERSION, "dist": {"tarball": install_geist.ARCHIVE, "integrity": integrity}}
    monkeypatch.setattr(install_geist, "STATIC", tmp_path)
    monkeypatch.setattr(install_geist, "download", lambda url, limit: data if url == install_geist.ARCHIVE else json.dumps(meta).encode())
    install_geist.main()
    assert (tmp_path / "Geist-Variable.woff2").read_bytes() == b"wOF2 mock"
    assert (tmp_path / "Geist-LICENSE.txt").is_file()
    meta["dist"]["integrity"] = "sha512-invalid"
    with pytest.raises(ValueError, match="integrity"):
        install_geist.main()
