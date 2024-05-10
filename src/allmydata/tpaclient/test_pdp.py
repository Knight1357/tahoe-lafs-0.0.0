import json
import os,unittest
from allmydata.tpaclient.tpa_client import TpaClient
from allmydata.util import base32


def loadData(filename='data.json'):
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, filename)
    with open(file_path, "r") as file:
        content = json.load(file)
    return content





#     需要启动节点
class FakePdp(unittest.TestCase):
    def setUp(self):
        print("build context")
        self.data = loadData()
        
    # @unittest.skip("")
    def test_immutable(self):
        print("immutable file pdp check")
        
        tpa = TpaClient()
        result = tpa.start(self.data)
        self.assertTrue(result)

        """
        """
    def test_mutable(self):
        """
        """


    def test_temp(self):
        storageIndex = '3ujqwk2jcsonkhydkasrfbytiq'.encode('utf-8')
        bytes = base32.a2b(storageIndex)
        print(bytes)

        