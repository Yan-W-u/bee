import subprocess


def convert(path):
    subprocess.run(["convert", path, "/tmp/out.png"], shell=False, check=True)
    return True
