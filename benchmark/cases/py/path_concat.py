def read_file(name):
    with open("/var/data/" + name, "r") as fh:
        return fh.read()
