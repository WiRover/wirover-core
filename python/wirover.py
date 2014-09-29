class WiRover:
    def __init__(self, debug = False):
        self.debug = debug
        self.wiroot = None
        self.node_id = None
        try:
            with open("/etc/wigateway.conf", 'r') as f:
                for line in f.readlines():
                    if "wiroot-address" in line and line.strip(" \t")[0] != "#":
                        self.wiroot = line.split("=")[1].strip(" \"\n;\r")
        except:
            if self.debug:
                print "Could not load node wiroot-address:", traceback.format_exc()
        try:
            with open("/etc/wirover.d/node_id",'r') as f:
                self.hash = f.readline()
        except:
            if self.debug:
                print "Could not load node hash:", traceback.format_exc()
