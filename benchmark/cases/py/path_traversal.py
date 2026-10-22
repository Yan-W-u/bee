import os


def read_user_file(name):
    with open(os.path.join("/var/data", name), "r") as fh:
        return fh.read()
