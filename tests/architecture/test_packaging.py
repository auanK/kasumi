"""Contract checks for Windows MSI, CPack DEB/RPM, and Arch Linux packaging."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import build_arch_package  # noqa: E402


WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"
WIX_UI_NS = "http://wixtoolset.org/schemas/v4/wxs/ui"
EXPECTED_UPGRADE_CODE = "B9E7C4A2-8D13-4F6E-9A51-2C6D8E4F1B70"


def read_cmake_version() -> str:
    cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    match = re.search(
        r"(?im)^\s*project\(kasumi\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)",
        cmake,
    )
    if match is None:
        raise AssertionError("could not parse kasumi version in CMakeLists.txt")
    return match.group(1)


class PackagingContractTest(unittest.TestCase):
    def test_arch_pkgbuild_version_matches_cmake(self):
        cmake_version = read_cmake_version()
        pkgbuild = (ROOT / "packaging" / "arch" / "PKGBUILD").read_text(encoding="utf-8")
        match = re.search(r"(?m)^pkgver=([0-9]+\.[0-9]+\.[0-9]+)\s*$", pkgbuild)
        self.assertIsNotNone(match, "PKGBUILD missing pkgver")
        self.assertEqual(match.group(1), cmake_version)
        self.assertIn("pkgname=kasumi", pkgbuild)
        self.assertIn("license=('MIT')", pkgbuild)
        self.assertIn("install=kasumi.install", pkgbuild)
        self.assertIn("install -Dm755 \"build/kasumi\" \"${pkgdir}/usr/bin/kasumi\"", pkgbuild)
        install_script = ROOT / "packaging" / "arch" / "kasumi.install"
        self.assertTrue(install_script.is_file())
        install_text = install_script.read_text(encoding="utf-8")
        self.assertIn("post_install()", install_text)
        self.assertIn("post_upgrade()", install_text)

    def test_cpack_deb_and_rpm_configuration_present(self):
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        for needle in (
            'install(\n    TARGETS kasumi',
            '${CMAKE_INSTALL_DOCDIR}',
            'set(CPACK_DEBIAN_KASUMI_FILE_NAME "kasumi-v${PROJECT_VERSION}-linux-x86_64.deb")',
            'set(CPACK_RPM_KASUMI_FILE_NAME "kasumi-v${PROJECT_VERSION}-linux-x86_64.rpm")',
            'set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA\n    "${PROJECT_SOURCE_DIR}/packaging/linux/deb/postinst")',
            'set(CPACK_RPM_POST_INSTALL_SCRIPT_FILE\n    "${PROJECT_SOURCE_DIR}/packaging/linux/rpm/post.sh")',
            'set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)',
            'set(CPACK_RPM_PACKAGE_AUTOREQPROV "yes")',
            'include(CPack)',
        ):
            self.assertIn(needle, cmake)

        deb_postinst = (ROOT / "packaging" / "linux" / "deb" / "postinst").read_bytes()
        rpm_post = (ROOT / "packaging" / "linux" / "rpm" / "post.sh").read_bytes()
        self.assertNotIn(b"\r\n", deb_postinst)
        self.assertNotIn(b"\r\n", rpm_post)
        self.assertTrue(deb_postinst.startswith(b"#!/bin/sh\n"))
        self.assertIn(b"upgraded", deb_postinst)
        self.assertIn(b"upgraded", rpm_post)

    def test_wix_manifest_and_license_rtf_contract(self):
        wxs_path = ROOT / "packaging" / "wix" / "kasumi.wxs"
        tree = ET.parse(wxs_path)
        root = tree.getroot()
        self.assertEqual(root.tag, f"{{{WIX_NS}}}Wix")

        pkg = root.find(f"{{{WIX_NS}}}Package")
        self.assertIsNotNone(pkg)
        self.assertEqual(pkg.attrib.get("Name"), "Kasumi")
        self.assertEqual(pkg.attrib.get("UpgradeCode"), EXPECTED_UPGRADE_CODE)
        self.assertEqual(pkg.attrib.get("Scope"), "perMachine")

        upgrade = pkg.find(f"{{{WIX_NS}}}MajorUpgrade")
        self.assertIsNotNone(upgrade)
        self.assertEqual(upgrade.attrib.get("AllowSameVersionUpgrades"), "yes")

        prop_ids = {p.attrib.get("Id") for p in pkg.findall(f"{{{WIX_NS}}}Property")}
        for expected_prop in (
            "INSTALLFOLDER",
            "PREVIOUS_VERSION",
            "KASUMI_WELCOME_TITLE",
            "KASUMI_WELCOME_DESC",
            "KASUMI_READY_TITLE",
            "KASUMI_READY_TEXT",
            "KASUMI_PROGRESS_TITLE",
            "KASUMI_EXIT_TITLE",
        ):
            self.assertIn(expected_prop, prop_ids)

        reg_names = {
            r.attrib.get("Name") for r in pkg.findall(f".//{{{WIX_NS}}}RegistryValue")
        }
        self.assertIn("InstallFolder", reg_names)
        self.assertIn("InstalledVersion", reg_names)

        seq = pkg.find(f"{{{WIX_NS}}}InstallUISequence")
        self.assertIsNotNone(seq)
        custom_elems = seq.findall(f"{{{WIX_NS}}}Custom")
        custom_conds = [c.attrib.get("Condition", "") for c in custom_elems]
        self.assertTrue(any("WIX_UPGRADE_DETECTED" in cond for cond in custom_conds))
        for c in custom_elems:
            self.assertNotEqual(c.attrib.get("Before"), "WelcomeDlg")
            self.assertNotEqual(c.attrib.get("After"), "WelcomeDlg")

        env_elems = pkg.findall(f".//{{{WIX_NS}}}Environment")
        path_envs = [
            e for e in env_elems
            if e.attrib.get("Name") == "PATH" and e.attrib.get("System") == "yes"
        ]
        self.assertEqual(len(path_envs), 1)
        self.assertEqual(path_envs[0].attrib.get("Value"), "[INSTALLFOLDER]")
        self.assertEqual(path_envs[0].attrib.get("Permanent"), "no")

        ui_elem = pkg.find(f"{{{WIX_UI_NS}}}WixUI")
        self.assertIsNotNone(ui_elem)
        self.assertEqual(ui_elem.attrib.get("Id"), "WixUI_InstallDir")
        self.assertEqual(ui_elem.attrib.get("InstallDirectory"), "INSTALLFOLDER")

        publish_elems = pkg.findall(f".//{{{WIX_NS}}}Publish")
        self.assertTrue(
            any(
                p.attrib.get("Dialog") == "WelcomeDlg"
                and p.attrib.get("Control") == "Next"
                and p.attrib.get("Value") == "VerifyReadyDlg"
                and p.attrib.get("Condition") == "WIX_UPGRADE_DETECTED"
                for p in publish_elems
            )
        )

        wxl_path = ROOT / "packaging" / "wix" / "KasumiStrings.wxl"
        wxl_root = ET.parse(wxl_path).getroot()
        self.assertEqual(
            wxl_root.tag, "{http://wixtoolset.org/schemas/v4/wxl}WixLocalization"
        )
        wxl_ids = {
            s.attrib.get("Id")
            for s in wxl_root.findall("{http://wixtoolset.org/schemas/v4/wxl}String")
        }
        for sid in (
            "WelcomeDlgTitle",
            "WelcomeDlgDescription",
            "VerifyReadyDlgInstallTitle",
            "VerifyReadyDlgInstallText",
            "ProgressDlgTitleInstalling",
            "ExitDialogTitle",
        ):
            self.assertIn(sid, wxl_ids)

        for comp in pkg.findall(f".//{{{WIX_NS}}}Component"):
            keypaths = [
                child for child in comp if child.attrib.get("KeyPath") == "yes"
            ]
            self.assertEqual(
                len(keypaths),
                1,
                f"Component {comp.attrib.get('Id')} must have exactly one KeyPath",
            )

        rtf = (ROOT / "packaging" / "wix" / "LICENSE.rtf").read_text(encoding="utf-8")
        self.assertTrue(rtf.lstrip().startswith(r"{\rtf1"))
        self.assertIn("MIT License", rtf)
        self.assertIn("Copyright (c) 2026 auanK", rtf)

    def test_arch_package_tar_layout_pkginfo_and_mtree(self):
        version = read_cmake_version()
        fake_binary_bytes = b"\x7fELFdummy-kasumi-binary-bytes-for-test"
        license_path = ROOT / "LICENSE"
        notices_path = ROOT / "THIRD_PARTY_NOTICES.md"
        install_path = ROOT / "packaging" / "arch" / "kasumi.install"
        license_bytes = license_path.read_bytes()
        notices_bytes = notices_path.read_bytes()
        install_bytes = install_path.read_bytes().replace(b"\r\n", b"\n")

        with tempfile.TemporaryDirectory(prefix="kasumi-arch-pkg-test-") as tmp:
            tmp_dir = Path(tmp)
            fake_bin = tmp_dir / "kasumi"
            fake_bin.write_bytes(fake_binary_bytes)
            out_tar = tmp_dir / f"kasumi-v{version}-linux-x86_64.pkg.tar"

            build_arch_package.build_arch_package(
                binary_path=fake_bin,
                version=version,
                output_path=out_tar,
                license_path=license_path,
                notices_path=notices_path,
                install_script_path=install_path,
                builddate=1700000000,
            )

            expected_order = [
                ".PKGINFO",
                ".MTREE",
                ".INSTALL",
                "usr",
                "usr/bin",
                "usr/bin/kasumi",
                "usr/share",
                "usr/share/licenses",
                "usr/share/licenses/kasumi",
                "usr/share/licenses/kasumi/LICENSE",
                "usr/share/licenses/kasumi/THIRD_PARTY_NOTICES.md",
            ]

            payloads: dict[str, bytes] = {}
            with tarfile.open(out_tar, "r:") as tf:
                members = tf.getmembers()
                self.assertEqual([m.name for m in members], expected_order)
                for member in members:
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.uname, "root")
                    self.assertEqual(member.gname, "root")
                    self.assertEqual(member.mtime, 1700000000)
                    if member.isdir():
                        self.assertEqual(member.mode, 0o755)
                    elif member.name == "usr/bin/kasumi":
                        self.assertEqual(member.mode, 0o755)
                    else:
                        self.assertEqual(member.mode, 0o644)
                    if member.isreg():
                        f = tf.extractfile(member)
                        assert f is not None
                        payloads[member.name] = f.read()

            pkginfo_text = payloads[".PKGINFO"].decode("utf-8")
            self.assertIn("pkgname = kasumi\n", pkginfo_text)
            self.assertIn(f"pkgver = {version}-1\n", pkginfo_text)
            expected_size = len(fake_binary_bytes) + len(license_bytes) + len(notices_bytes)
            self.assertIn(f"size = {expected_size}\n", pkginfo_text)
            self.assertIn("arch = x86_64\n", pkginfo_text)
            self.assertIn("depend = glibc\n", pkginfo_text)
            self.assertIn("depend = gcc-libs\n", pkginfo_text)

            mtree_text = gzip.decompress(payloads[".MTREE"]).decode("utf-8")
            self.assertTrue(mtree_text.startswith("#mtree\n"))

            for tar_name, expected_data in (
                (".PKGINFO", payloads[".PKGINFO"]),
                (".INSTALL", install_bytes),
                ("usr/bin/kasumi", fake_binary_bytes),
                ("usr/share/licenses/kasumi/LICENSE", license_bytes),
                ("usr/share/licenses/kasumi/THIRD_PARTY_NOTICES.md", notices_bytes),
            ):
                self.assertEqual(payloads[tar_name], expected_data)
                md5_hex = hashlib.md5(expected_data).hexdigest()
                sha256_hex = hashlib.sha256(expected_data).hexdigest()
                line = next(
                    (l for l in mtree_text.splitlines() if l.startswith(f"./{tar_name} ")),
                    None,
                )
                self.assertIsNotNone(line, f"missing .MTREE line for {tar_name}")
                self.assertIn(f"size={len(expected_data)}", line)
                self.assertIn(f"md5digest={md5_hex}", line)
                self.assertIn(f"sha256digest={sha256_hex}", line)

            zstd = shutil.which("zstd")
            if zstd:
                out_zst = tmp_dir / f"kasumi-v{version}-linux-x86_64.pkg.tar.zst"
                build_arch_package.build_arch_package(
                    binary_path=fake_bin,
                    version=version,
                    output_path=out_zst,
                    license_path=license_path,
                    notices_path=notices_path,
                    install_script_path=install_path,
                    builddate=1700000000,
                    zstd_exe=zstd,
                )
                decompressed = subprocess.run(
                    [zstd, "-dc", str(out_zst)],
                    capture_output=True,
                    check=True,
                ).stdout
                with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as ztf:
                    self.assertEqual([m.name for m in ztf.getmembers()], expected_order)


if __name__ == "__main__":
    unittest.main(verbosity=2)
