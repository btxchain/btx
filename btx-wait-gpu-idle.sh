#!/usr/bin/env bash
# Wait until the GPU power draw drops below 60W (in-flight mining call drained).
set -u
for i in $(seq 1 24); do
    P=$(nvidia-smi --query-gpu=power.draw --format=csv,noheader,nounits | head -1)
    P=${P%.*}
    if [ "${P:-999}" -lt 60 ]; then
        echo "GPU idle (${P}W) after $((i * 5))s"
        break
    fi
    sleep 5
done
nvidia-smi --query-gpu=utilization.gpu,power.draw --format=csv,noheader
