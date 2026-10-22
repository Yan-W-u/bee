import os


def read_user_file(name):
    root = os.path.realpath("/var/data")
    target = os.path.realpath(os.path.join(root, os.path.basename(name)))
    if not target.startswith(root + os.sep):
        raise ValueError("越界")
    with open(target, "r") as fh:
        return fh.read()
