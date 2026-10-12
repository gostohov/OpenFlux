#!/usr/bin/env bash
set -euo pipefail
version=${1:?Usage: scripts/release-fork.sh VERSION}
[[ $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+[-.a-zA-Z0-9]*$ ]] || { echo 'Invalid release version' >&2; exit 1; }
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
git diff --quiet
git diff --cached --quiet
commit=$(git rev-parse HEAD)
release_dir="$repo_dir/dist/release"
mkdir -p "$release_dir"
for platform in linux windows; do
  extension=''
  [[ $platform != windows ]] || extension='.exe'
  CGO_ENABLED=0 GOOS=$platform GOARCH=amd64 go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.buildVersion=$version -X main.buildCommit=$commit" \
    -o "$release_dir/openflux-$platform-amd64$extension" .
done
python3 - "$repo_dir" "$release_dir" "$version" "$commit" <<'PY'
import gzip, hashlib, io, json, pathlib, subprocess, sys, tarfile, zipfile
repo, out = map(pathlib.Path, sys.argv[1:3])
version, commit = sys.argv[3:5]
readme = (repo / 'docs/reliability-and-security.md').read_bytes()
license_data = (repo / 'LICENSE').read_bytes()
notice_data = (repo / 'NOTICE').read_bytes()
assets = []
for platform in ('linux', 'windows'):
    name = f'openflux-{platform}-amd64' + ('.exe' if platform == 'windows' else '')
    binary = out / name
    assets.append(binary)
    files = [('openflux.exe' if platform == 'windows' else 'openflux', binary.read_bytes(), 0o755),
             ('README.md', readme, 0o644), ('LICENSE', license_data, 0o644), ('NOTICE', notice_data, 0o644)]
    archive = out / f'openflux-{version}-{platform}-amd64{ ".zip" if platform == "windows" else ".tar.gz" }'
    if platform == 'windows':
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for filename, data, mode in files:
                info = zipfile.ZipInfo(filename, date_time=(2020, 1, 1, 0, 0, 0))
                info.external_attr = (0o100000 | mode) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
    else:
        with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
            for filename, data, mode in files:
                info = tarfile.TarInfo(filename)
                info.size, info.mode, info.mtime = len(data), mode, 0
                tar.addfile(info, io.BytesIO(data))
    assets.append(archive)
metadata = out / 'build-info.json'
metadata.write_text(json.dumps({'version': version, 'commit': commit,
    'go': subprocess.check_output(['go', 'version'], text=True).strip(),
    'platforms': ['windows/amd64', 'linux/amd64'], 'forward_secrecy': 'opt-in Noise_NNpsk0_25519_AESGCM_SHA256'}, indent=2) + '\n')
assets.append(metadata)
(out / 'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n' for asset in assets))
print(f'Packaged {version} from {commit}')
PY
