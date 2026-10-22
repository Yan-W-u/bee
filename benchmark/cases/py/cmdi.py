import os


def convert(path):
    os.system("convert " + path + " /tmp/out.png")
    return True
