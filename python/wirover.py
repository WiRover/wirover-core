import os

class WiRover:
    def _get_root_server(self, path):
        try:
	    with open(path, 'r') as f:
		for line in f.readlines():
		    if "wiroot-address" in line and line.strip(" \t")[0] != "#":
			return line.split("=")[1].strip(" \"\n;\r")
        except:
            if self.debug:
                print "Could not load node wiroot-address:", traceback.format_exc()
            return None

    def __init__(self, debug = False):
        self.debug = debug
        self.is_gateway = False
        self.is_controller = False
        self.is_rootserver = False
        self.wiroot = None
        self.node_id = None

	if os.path.exists("/etc/wigateway.conf"):
	    self.is_gateway = True
            self.wiroot = self._get_root_server("/etc/wigateway.conf")

	if os.path.exists("/etc/wicontroller.conf"):
	    self.is_controller = True
            self.wiroot = self._get_root_server("/etc/wicontroller.conf")

	if os.path.exists("/etc/wiroot.conf"):
	    self.is_rootserver = True

        try:
            with open("/etc/wirover.d/node_id",'r') as f:
                self.hash = f.readline()
        except:
            if self.debug:
                print "Could not load node hash:", traceback.format_exc()
