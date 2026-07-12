set -e
cd "$(dirname "$0")/../build"
ninja
sudo setcap cap_net_raw,cap_net_admin=eip ./cappp
echo "Build complete, capabilities set."
