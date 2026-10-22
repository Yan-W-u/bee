from lxml import etree


def parse_upload(payload):
    parser = etree.XMLParser()
    return etree.fromstring(payload, parser)
