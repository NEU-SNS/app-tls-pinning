#!/bin/sh
for server in achtung02 achtung03 achtung04 achtung05 achtung06 achtung07 achtung08 achtung09 achtung10 achtung11 achtung12 achtung13 achtung14 achtung15  achtung16 achtung17; do
    ssh $server << EOF
    echo "######################################################"
    hostname
    cd ~/certificate-pinning/StaticAnalysis/trustManager
    mkdir -p logs
    nohup ./mcg_trust_manager_finder.py > logs/$server.nohup 2>&1 &
EOF
done
