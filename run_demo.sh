$HOME/p4lang/p4c-bmv2/p4c_bm/__main__.py p4src/damit.p4 --json damit.json

sudo rm *.pcap

sudo ./simple_switch > /dev/null 2>&1
sudo PYTHONPATH=$PYTHONPATH:$HOME/p4lang/bmv2/mininet python topo.py \
    --behavioral-exe ./simple_switch \
    --json ./damit.json \
    --cli ./sswitch_CLI.py \
    --topo ./topo.txt \
    --default ./default.txt
