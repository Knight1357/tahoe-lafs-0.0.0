from tpaclient import Tpa
import threading
def get_config_data():
    msg = ""
    datapath = "src/getdata"
    with open(datapath, "r") as f:
        msg = f.read()
    return msg
def test_mshare_block_challengeblock_seq():
    data = get_config_data()
    tpa = Tpa(data)
    (vis, iis) = tpa.get_challenge_seq()
    for shnum, addr in tpa.shares.items():
        ip, port = addr.split(":")
        t = threading.Thread(target=tpa.send_challenge, args=(vis, iis, shnum, ip, port, tpa))
        t.start() 
if __name__ == '__main__':
    test_mshare_block_challengeblock_seq()  