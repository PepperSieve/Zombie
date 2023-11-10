#! /bin/bash

# sample command
# ./iptables_configure.sh m400 sync 10
# ./iptables_configure.sh c6525-25g async
sudo iptables -F
if [ "$1" == "m400" ]; then
  EXT="enp1s0"
  INT="enp1s0d1"
elif [ "$1" == "c6525-25g" ]; then
  EXT="eno33"
  INT="enp65s0f0"
fi
echo 1 > /proc/sys/net/ipv4/ip_forward #Tell the system it is OK to forward IP packets
sudo iptables -t nat -A POSTROUTING -o $EXT -j MASQUERADE
if [ "$2" == "sync" ]; then
    for i in `seq 5 $(($3 + 5))`
    do
        echo "192.168.0.$i $(($i - 5))"
        sudo iptables -A FORWARD -i $EXT -o $INT -m state --state RELATED,ESTABLISHED -d 192.168.0.$i -j NFQUEUE --queue-num $(($i - 5))
        sudo iptables -A FORWARD -i $INT -o $EXT -s 192.168.0.$i -j NFQUEUE --queue-num $(($i - 5))
    done
else
    sudo iptables -A FORWARD -i $EXT -o $INT -m state --state RELATED,ESTABLISHED -j NFQUEUE --queue-num 0
    sudo iptables -A FORWARD -i $INT -o $EXT -j NFQUEUE --queue-num 0
fi
