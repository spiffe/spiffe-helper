$goVersion = (Get-Content -Path "..\go.mod" | Select-String -Pattern "^go\s+(\d+\.\d+\.\d+)" | ForEach-Object { $_.Matches[0].Groups[1].Value })
$spireVersion=$(Get-Content -Path "spire.version")

cd ..
docker --debug build --build-arg go_version=${goVersion} -t spiffe-helper:local .
cd integrationTest
docker build --build-arg spire_version=${spireVersion} -t spiffe-helper-it:latest .
