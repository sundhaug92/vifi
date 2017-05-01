for i in `seq 1 11`;
do
    echo Channel $i
    airodump-ng -w TEST-INPUT-CHANNEL-$i -c $i --manufacturer --uptime --beacons --output-format pcap wlan0 & sleep 10m; kill $!
done
