#!/bin/zsh
# Build the universal macOS app and seal it without rewriting bundled HDC.
# hdc and libusb_shared.dylib already carry Huawei's Developer ID signature.
# Replacing that signature changes the file hash, and the app then refuses to start.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
target=${CARGO_TARGET_DIR:-"$root/target"}
app="$target/universal-apple-darwin/release/bundle/macos/HHI.app"
dist="$root/dist"

cd "$root/app"
npx --yes @tauri-apps/cli@2 build --target universal-apple-darwin

if [[ ! -d "$app" ]]; then
  echo "没有找到 $app" >&2
  exit 1
fi

find "$app" -type f -print0 | while IFS= read -r -d '' file; do
  case "$file" in
    */vendor/hdc/*) continue ;;
  esac
  if file -b "$file" | grep -q "Mach-O"; then
    codesign --force --sign - "$file"
  fi
done
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"

python3 - "$app" "$root/config/hdc-policy.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

app = Path(sys.argv[1])
policy = json.loads(Path(sys.argv[2]).read_text())
bundled = json.loads((app / "Contents/Resources/_up_/_up_/config/hdc-policy.json").read_text())
if bundled != policy:
    raise SystemExit("安装包里的 hdc-policy.json 和仓库不一致")
base = app / "Contents/Resources/_up_/_up_/vendor/hdc"
for bundle in policy["bundles"]:
    path = base / bundle["platform"] / bundle["fileName"]
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != bundle["sha256"]:
        raise SystemExit(f"{bundle['platform']} 哈希是 {digest}，策略是 {bundle['sha256']}")
    print(f"ok {bundle['platform']} {digest}")
PY

version=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$root/app/src-tauri/tauri.conf.json")
rm -rf "$dist/HHI.app"
mkdir -p "$dist"
cp -R "$app" "$dist/HHI.app"
codesign --verify --deep --strict "$dist/HHI.app"
rm -f "$dist/HHI_${version}_macos.dmg"
hdiutil create -volname HHI -srcfolder "$dist/HHI.app" -ov -format UDZO "$dist/HHI_${version}_macos.dmg"
echo "已生成 $dist/HHI_${version}_macos.dmg"
