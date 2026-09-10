import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tarfile
import zipfile
import platform
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]

def run(arguments, **options):
    subprocess.run([str(value) for value in arguments], cwd=ROOT, check=True, **options)

def plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))

def cargo(target, environment=None, zig=False):
    run(["cargo", "zigbuild" if zig else "build", "--release", "--workspace", "--locked", "--target", target], env=environment)
    return ROOT / "target" / target / "release"

def requirements(directory):
    for name in ["Mosaic_Prototype_Plan_v2.docx", "fixes.md"]:
        shutil.copy2(ROOT / name, directory / name)
    shutil.copy2(ROOT / "native/README.md", directory / "Native-README.md")

def apple(args, output):
    mobile = args.platform == "ios"
    target = args.target or ("aarch64-apple-ios" if mobile else "aarch64-apple-darwin")
    allowed = ["aarch64-apple-ios"] if mobile else ["aarch64-apple-darwin", "x86_64-apple-darwin"]
    if target not in allowed:
        raise ValueError("unsupported Apple build target")
    sdk = "iphoneos" if mobile else "macosx"
    sdk_path = subprocess.check_output(["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True).strip()
    environment = os.environ.copy()
    environment["IPHONEOS_DEPLOYMENT_TARGET" if mobile else "MACOSX_DEPLOYMENT_TARGET"] = "17.0" if mobile else "14.0"
    binaries = cargo(target, environment)
    run(["cargo", "rustc", "--release", "--locked", "-p", "mosaic-native", "--lib", "--crate-type", "staticlib", "--target", target], env=environment)
    team = args.team or "UNSIGNED"
    bundle = args.bundle
    provider = bundle + ".tunnel"
    group = team + "." + bundle + ".shared"
    application = output / "Mosaic.app"
    application.mkdir()
    contents = application if mobile else application / "Contents"
    executables = contents if mobile else contents / "MacOS"
    executables.mkdir(parents=True, exist_ok=True)
    extension = contents / ("PlugIns" if mobile else "Library/SystemExtensions") / (provider + (".appex" if mobile else ".systemextension"))
    extension_contents = extension if mobile else extension / "Contents"
    extension_binaries = extension_contents if mobile else extension_contents / "MacOS"
    extension_binaries.mkdir(parents=True)
    common = {"CFBundleDevelopmentRegion": "en", "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "1", "CFBundleName": "Mosaic"}
    host = {**common, "CFBundleIdentifier": bundle, "CFBundleExecutable": "Mosaic" if mobile else "mosaic-control", "CFBundlePackageType": "APPL", "MosaicProvider": provider, "MosaicKeychainGroup": group}
    if mobile:
        host.update({"MinimumOSVersion": "17.0", "UIDeviceFamily": [1, 2], "UILaunchScreen": {}, "UISupportedInterfaceOrientations": ["UIInterfaceOrientationPortrait", "UIInterfaceOrientationLandscapeLeft", "UIInterfaceOrientationLandscapeRight"]})
    else:
        host.update({"LSMinimumSystemVersion": "14.0", "LSUIElement": True})
    plist(contents / "Info.plist", host)
    provider_info = {**common, "CFBundleIdentifier": provider, "CFBundleExecutable": "MosaicTunnel", "CFBundlePackageType": "XPC!" if mobile else "SYSX"}
    if mobile:
        provider_info.update({"MinimumOSVersion": "17.0", "NSExtension": {"NSExtensionPointIdentifier": "com.apple.networkextension.packet-tunnel", "NSExtensionPrincipalClass": "MosaicTunnel.PacketTunnel"}})
    else:
        provider_info.update({"LSMinimumSystemVersion": "14.0", "NetworkExtension": {"NEMachServiceName": team + "." + provider, "NEProviderClasses": {"com.apple.networkextension.packet-tunnel": "MosaicTunnel.PacketTunnel"}}})
    plist(extension_contents / "Info.plist", provider_info)
    architecture = "arm64" if target.startswith("aarch64") else "x86_64"
    swift_target = architecture + ("-apple-ios17.0" if mobile else "-apple-macosx14.0")
    flags = ["xcrun", "--sdk", sdk, "swiftc", "-O", "-swift-version", "5", "-warnings-as-errors", "-sdk", sdk_path, "-target", swift_target, "-import-objc-header", ROOT / "native/apple/Bridge.h", binaries / "libmosaic_native.a", "-framework", "NetworkExtension", "-framework", "Network", "-framework", "Security", "-framework", "SystemConfiguration"]
    sources = ROOT / "native/apple"
    extension_flags = ["-application-extension", "-Xlinker", "-e", "-Xlinker", "_NSExtensionMain"] if mobile else [sources / "Extension.swift"]
    run(flags + ["-module-cache-path", output / "tunnel-cache", "-module-name", "MosaicTunnel", sources / "PacketTunnel.swift", *extension_flags, "-o", extension_binaries / "MosaicTunnel"])
    host_flags = [sources / "Mobile.swift"] if mobile else [sources / "Control.swift", "-framework", "SystemExtensions", "-framework", "AppKit"]
    run(flags + ["-module-cache-path", output / "application-cache", "-module-name", "Mosaic", sources / "Manager.swift", *host_flags, "-o", executables / host["CFBundleExecutable"]])
    if not mobile:
        shutil.copy2(binaries / "mosaic-client", executables / "mosaic-client")
    kind = "packet-tunnel-provider" if mobile else "packet-tunnel-provider-systemextension"
    entitlements = {"com.apple.developer.networking.networkextension": [kind], "keychain-access-groups": [group]}
    host_entitlements = dict(entitlements)
    provider_entitlements = dict(entitlements)
    host_entitlements["com.apple.developer.team-identifier"] = team
    provider_entitlements["com.apple.developer.team-identifier"] = team
    if not mobile:
        host_entitlements["com.apple.application-identifier"] = team + "." + bundle
        provider_entitlements["com.apple.application-identifier"] = team + "." + provider
    if mobile:
        host_entitlements["application-identifier"] = team + "." + bundle
        provider_entitlements["application-identifier"] = team + "." + provider
    else:
        host_entitlements["com.apple.developer.system-extension.install"] = True
        provider_entitlements.update({"com.apple.security.app-sandbox": True, "com.apple.security.network.client": True})
    plist(output / "application.entitlements", host_entitlements)
    plist(output / "tunnel.entitlements", provider_entitlements)
    if args.unsigned:
        identity = "-"
    else:
        if not all([args.identity, args.team, args.app_profile, args.extension_profile]):
            raise ValueError("signing identity, team and both provisioning profiles are required; --unsigned builds development artifacts only")
        identity = args.identity
        for profile, destination, identifier in [(args.app_profile, contents, bundle), (args.extension_profile, extension_contents, provider)]:
            decoded = plistlib.loads(subprocess.check_output(["security", "cms", "-D", "-i", str(profile)]))
            identifier_key = "application-identifier" if mobile else "com.apple.application-identifier"
            if decoded.get("Entitlements", {}).get(identifier_key) != team + "." + identifier:
                raise ValueError("provisioning profile does not match the selected team and bundle")
            shutil.copy2(profile, destination / ("embedded.mobileprovision" if mobile else "embedded.provisionprofile"))
    for package, entitlement in [(extension, "tunnel.entitlements"), (application, "application.entitlements")]:
        if package == application and not mobile:
            run(["codesign", "--force", "--sign", identity, "--options", "runtime", executables / "mosaic-client"])
        run(["codesign", "--force", "--sign", identity, "--options", "runtime", "--entitlements", output / entitlement, package])
        run(["codesign", "--verify", "--strict", package])
    requirements(output)
    if args.unsigned:
        return target, "Unsigned development app compiled; installation acceptance requires signed provisioning"
    if mobile:
        with zipfile.ZipFile(output / "Mosaic.ipa", "w", zipfile.ZIP_DEFLATED) as archive:
            for path in application.rglob("*"):
                archive.write(path, Path("Payload/Mosaic.app") / path.relative_to(application))
    else:
        if not args.installer_identity or not args.notary_profile:
            raise ValueError("Developer ID Installer identity and notarization keychain profile are required for a distributable macOS package")
        installation = output / "installation/Applications"
        installation.mkdir(parents=True)
        shutil.copytree(application, installation / "Mosaic.app")
        package = output / "Mosaic.pkg"
        run(["pkgbuild", "--root", output / "installation", "--identifier", bundle, "--version", "0.1.0", "--install-location", "/", "--sign", args.installer_identity, package])
        run(["xcrun", "notarytool", "submit", package, "--keychain-profile", args.notary_profile, "--wait"])
        run(["xcrun", "stapler", "staple", package])
    return target, "Signed package built; physical platform acceptance remains required"

def linux(args, output):
    target = args.target or subprocess.check_output(["rustc", "-vV"], text=True).split("host: ")[1].splitlines()[0]
    if "linux" not in target:
        raise ValueError("build the Linux package on Linux or provide a verified Linux cross toolchain")
    binaries = cargo(target, zig=args.zig)
    for name in ["mosaic-client", "mosaic-service", "mosaic-relay"]:
        shutil.copy2(binaries / name, output / name)
    requirements(output)
    shutil.copy2(ROOT / "configs/client-native.example.json", output / "client-native.example.json")
    with tarfile.open(output / "Mosaic.tar.gz", "w:gz") as archive:
        for path in sorted(output.iterdir()):
            if path.name != "Mosaic.tar.gz": archive.add(path, arcname=path.name)
    return target, "Compiled Linux installation bundle built; dedicated Linux acceptance remains required"

def android(args, output):
    sdk = Path(args.sdk or os.environ.get("ANDROID_HOME", "")).resolve()
    ndk = sdk / "ndk/28.2.13676358"
    host = "darwin-x86_64" if sys.platform == "darwin" else "windows-x86_64" if sys.platform == "win32" else "linux-x86_64"
    compiler = ndk / "toolchains/llvm/prebuilt" / host / "bin"
    if not compiler.is_dir():
        raise ValueError("Android NDK 28.2.13676358 is required")
    for target, abi, triple in [("aarch64-linux-android", "arm64-v8a", "aarch64-linux-android"), ("x86_64-linux-android", "x86_64", "x86_64-linux-android")]:
        environment = os.environ.copy()
        linker = compiler / (triple + "29-clang" + (".cmd" if sys.platform == "win32" else ""))
        environment["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] = str(linker)
        environment["CC_" + target.replace("-", "_")] = str(linker)
        environment["AR_" + target.replace("-", "_")] = str(compiler / "llvm-ar")
        environment["CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUSTFLAGS"] = "-C link-arg=-Wl,-z,max-page-size=16384"
        run(["cargo", "rustc", "--release", "--locked", "-p", "mosaic-native", "--lib", "--crate-type", "cdylib", "--target", target], env=environment)
        destination = ROOT / "native/android/app/src/main/jniLibs" / abi
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "target" / target / "release/libmosaic_native.so", destination / "libmosaic_native.so")
    environment = os.environ.copy()
    environment["ANDROID_HOME"] = str(sdk)
    run(["gradle", "--no-daemon", "-p", ROOT / "native/android", "assembleDebug" if args.unsigned else "assembleRelease", "lint"], env=environment)
    variant = "debug" if args.unsigned else "release"
    apk = ROOT / "native/android/app/build/outputs/apk" / variant / ("app-debug.apk" if args.unsigned else "app-release-unsigned.apk")
    destination = output / "Mosaic.apk"
    signer = ["java", "--enable-native-access=ALL-UNNAMED", "-jar", sdk / "build-tools/36.0.0/lib/apksigner.jar"]
    if args.unsigned:
        shutil.copy2(apk, destination)
    else:
        if not args.keystore or not args.key_alias or not os.environ.get("MOSAIC_STORE_PASSWORD") or not os.environ.get("MOSAIC_KEY_PASSWORD"):
            raise ValueError("release signing requires a keystore, alias and MOSAIC_STORE_PASSWORD/MOSAIC_KEY_PASSWORD environment values")
        run(signer + ["sign", "--ks", args.keystore, "--ks-key-alias", args.key_alias, "--ks-pass", "env:MOSAIC_STORE_PASSWORD", "--key-pass", "env:MOSAIC_KEY_PASSWORD", "--out", destination, apk])
    run(signer + ["verify", destination])
    requirements(output)
    return "arm64-v8a,x86_64", "Android APK built; device routing, lockdown and recovery acceptance remains required"

def windows(args, output):
    if sys.platform != "win32":
        raise ValueError("build the Windows installer on Windows with WiX and the Windows SDK")
    target = args.target or "x86_64-pc-windows-msvc"
    if target != "x86_64-pc-windows-msvc":
        raise ValueError("the Windows package targets x64 MSVC")
    binaries = cargo(target)
    for name in ["mosaic-client.exe", "mosaic-service.exe"]:
        shutil.copy2(binaries / name, output / name)
    archive = urllib.request.urlopen("https://www.wintun.net/builds/wintun-0.14.1.zip", timeout=60).read(16777216)
    if hashlib.sha256(archive).hexdigest() != "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51":
        raise ValueError("Wintun distribution checksum mismatch")
    import io
    with zipfile.ZipFile(io.BytesIO(archive)) as driver:
        (output / "wintun.dll").write_bytes(driver.read("wintun/bin/amd64/wintun.dll"))
        (output / "Wintun-LICENSE.txt").write_bytes(driver.read("wintun/LICENSE.txt"))
    if not args.unsigned:
        if not args.identity:
            raise ValueError("Windows release signing requires the certificate thumbprint")
        for name in ["mosaic-client.exe", "mosaic-service.exe"]:
            run(["signtool", "sign", "/sha1", args.identity, "/fd", "SHA256", "/tr", "http://timestamp.digicert.com", "/td", "SHA256", output / name])
    run(["signtool", "verify", "/pa", output / "wintun.dll"])
    wix = ET.Element("Wix", xmlns="http://wixtoolset.org/schemas/v4/wxs")
    package = ET.SubElement(wix, "Package", Name="Mosaic", Manufacturer="Mosaic", Version="0.1.0", UpgradeCode="6D6F7361-6963-4471-A023-85017974B001", Scope="perMachine")
    ET.SubElement(package, "MajorUpgrade", DowngradeErrorMessage="A newer Mosaic version is installed. Disconnect Mosaic before changing its installation.")
    ET.SubElement(package, "MediaTemplate", EmbedCab="yes")
    directory = ET.SubElement(ET.SubElement(package, "StandardDirectory", Id="ProgramFiles64Folder"), "Directory", Id="INSTALLFOLDER", Name="Mosaic")
    feature = ET.SubElement(package, "Feature", Id="Mosaic", Title="Mosaic", Level="1")
    for index, name in enumerate(["mosaic-client.exe", "mosaic-service.exe", "wintun.dll", "Wintun-LICENSE.txt"]):
        component = ET.SubElement(directory, "Component", Id="File" + str(index), Guid="*")
        ET.SubElement(component, "File", Id="Client" if index == 0 else "Binary" + str(index), Source=str(output / name), KeyPath="yes")
        ET.SubElement(feature, "ComponentRef", Id="File" + str(index))
    ET.SubElement(package, "CustomAction", Id="Setup", FileRef="Client", ExeCommand='setup --owner-sid "[UserSID]"', Execute="deferred", Impersonate="no", Return="check")
    ET.SubElement(package, "CustomAction", Id="Remove", FileRef="Client", ExeCommand="uninstall", Execute="deferred", Impersonate="no", Return="check")
    sequence = ET.SubElement(package, "InstallExecuteSequence")
    ET.SubElement(sequence, "Custom", Action="Setup", After="InstallFiles", Condition='NOT Installed OR REINSTALL')
    ET.SubElement(sequence, "Custom", Action="Remove", Before="RemoveFiles", Condition='REMOVE="ALL"')
    source = output / "installer.wxs"
    ET.ElementTree(wix).write(source, encoding="utf-8", xml_declaration=True)
    installer = output / "Mosaic.msi"
    run(["wix", "build", "-arch", "x64", "-o", installer, source])
    if not args.unsigned:
        run(["signtool", "sign", "/sha1", args.identity, "/fd", "SHA256", "/tr", "http://timestamp.digicert.com", "/td", "SHA256", installer])
        run(["signtool", "verify", "/pa", installer])
    requirements(output)
    return target, "Windows installer built with the signed Wintun component; installed Windows acceptance remains required"

def source_hash():
    digest = hashlib.sha256()
    names = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).split(b"\0")
    names.extend([b"fixes.md", b"Mosaic_Prototype_Plan_v2.docx"])
    for name in sorted(set(names)):
        if not name: continue
        path = ROOT / os.fsdecode(name)
        if path.is_file(): digest.update(name + b"\0" + path.read_bytes())
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Build native Mosaic components; installation acceptance is reported separately.")
    parser.add_argument("platform", choices=["macos", "ios", "linux", "windows", "android"])
    parser.add_argument("--target")
    parser.add_argument("--zig", action="store_true")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--keystore", type=Path)
    parser.add_argument("--key-alias")
    parser.add_argument("--unsigned", action="store_true")
    parser.add_argument("--team")
    parser.add_argument("--bundle", default="net.mosaic.client")
    parser.add_argument("--identity")
    parser.add_argument("--installer-identity")
    parser.add_argument("--app-profile", type=Path)
    parser.add_argument("--extension-profile", type=Path)
    parser.add_argument("--notary-profile")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"platform": args.platform, "build": "FAIL", "acceptance": "BLOCKED", "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest()}
    report["build_os"] = platform.platform()
    report["build_arch"] = platform.machine()
    report["source_revision"] = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    report["source_sha256"] = source_hash()
    try:
        target, detail = {"linux": linux, "windows": windows, "android": android, "macos": apple, "ios": apple}[args.platform](args, output)
        if source_hash() != report["source_sha256"]:
            raise ValueError("source changed during package creation; rebuild from stable source")
        report.update({"target": target, "build": "PASS", "detail": detail})
        print("PASS: " + detail)
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        report["detail"] = "Native build, SDK, signing or package verification failed; inspect the build output"
        print("FAIL: " + report["detail"], file=sys.stderr)
        return 1
    finally:
        report["artifacts"] = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest() for path in output.rglob("*") if path.is_file() and path.suffix in [".apk", ".ipa", ".msi", ".pkg", ".gz"]}
        (output / "build.json").write_text(json.dumps(report, indent=2) + "\n")

if __name__ == "__main__":
    sys.exit(main())
