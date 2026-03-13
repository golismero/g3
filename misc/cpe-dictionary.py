#!/usr/bin/env python3

# Script to download the official CPE dictionary from MITRE and serialize it in a SQLite database.

import io
import os
import json
import gzip
import sqlite3
import os.path
import urllib.request

from lxml import etree
from lxml.objectify import deannotate

cpe_titles = {}         # cpe -> title
cpe_references = {}     # cpe -> [ href ]

xml_filename = "official-cpe-dictionary_v2.3.xml"
xml_url = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/" + xml_filename + ".gz"
xml_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), xml_filename)

titles_file = "cpe-titles.json"
references_file = "cpe-references.json"

sqlite_file = "cpe.db"

# https://stackoverflow.com/a/71886208/426293
def remove_namespaces(root):
    for elem in root.getiterator():
        if not (
                isinstance(elem, etree._Comment)
                or isinstance(elem, etree._ProcessingInstruction)
        ):
            localname = etree.QName(elem).localname
            if elem.tag != localname:
                elem.tag = etree.QName(elem).localname
            for attr_name in elem.attrib:
                local_attr_name = etree.QName(attr_name).localname
                if attr_name != local_attr_name:
                    attr_value = elem.attrib[attr_name]
                    del elem.attrib[attr_name]
                    elem.attrib[local_attr_name] = attr_value
    deannotate(root, cleanup_namespaces=True)

def parse_xml():
    global cpe_titles
    global cpe_references
    if not cpe_titles or not cpe_references:
        if not os.path.exists(xml_file):
            print("Downloading " + xml_url)
            r = urllib.request.urlopen(xml_url)
            try:
                xml = r.read()
                assert xml
            finally:
                r.close()
            xml = gzip.decompress(xml)
            with open(xml_file, "w") as fd:
                try:
                    fd.write(xml.decode("utf8"))
                except:
                    os.unlink(xml_file)
                    raise
            del xml

        print("Loading " + xml_filename)
        root = etree.parse(xml_file).getroot()
        remove_namespaces(root)
        print("Parsing " + xml_filename)
        for item in root:
            if item.tag != "cpe-item":
                continue
            name = item.attrib["name"]
            for child in item:
                tag = child.tag
                if tag == "title":
                    if child.attrib["lang"] != "en-US":
                        continue
                    assert name not in cpe_titles, etree.tostring(child)
                    cpe_titles[name] = child.text
                elif tag == "references":
                    assert name not in cpe_references, etree.tostring(child)
                    cpe_references[name] = [x.attrib["href"] for x in child]
        assert not set(cpe_references.keys()).difference(set(cpe_titles.keys()))

def save_json():
    global cpe_titles
    global cpe_references
    if not os.path.exists(titles_file) or not os.path.exists(references_file):

        print("Saving to: " + titles_file)
        with open(titles_file, "w") as fd:
            json.dump(cpe_titles, fd)

        print("Saving to: " + references_file)
        with open(references_file, "w") as fd:
            json.dump(cpe_references, fd)

        print("Verifying: " + titles_file)
        with open(titles_file, "r") as fd:
            cpe_titles = json.load(fd)
        print("Verifying: " + references_file)
        with open(references_file, "r") as fd:
            cpe_references = json.load(fd)

def save_sqlite():
    if not os.path.exists(sqlite_file):
        print("Saving to: " + sqlite_file)
        max_cpe_length = 0
        max_title_length = 0
        max_reference_length = 0
        for cpe, title in cpe_titles.items():
            if len(cpe) > max_cpe_length:
                max_cpe_length = len(cpe)
            if len(title) > max_title_length:
                max_title_length = len(title)
        for cpe, references in cpe_references.items():
            if len(cpe) > max_cpe_length:
                max_cpe_length = len(cpe)
            len_ref = max(len(ref) for ref in references)
            if len_ref > max_reference_length:
                max_reference_length = len_ref
        try:
            con = sqlite3.connect(sqlite_file)
            cur = con.cursor()
            cur.execute("CREATE TABLE titles(cpe TEXT(%d) NOT NULL, title TEXT(%d) NOT NULL)" % (max_cpe_length, max_title_length))
            cur.execute("CREATE TABLE refs(cpe TEXT(%d) NOT NULL, href TEXT(%d) NOT NULL)" % (max_cpe_length, max_reference_length))
            cur.execute("CREATE UNIQUE INDEX idx_titles ON titles(cpe)")
            cur.execute("CREATE INDEX idx_refs ON refs(cpe)")
            cur.executemany("INSERT INTO titles VALUES (?, ?)", [(cpe, title) for cpe, title in cpe_titles.items()])
            for cpe, href in cpe_references.items():
                cur.executemany("INSERT INTO refs VALUES (?, ?)", [(cpe, x) for x in href])
            con.commit()
            cur.execute("VACUUM")
            con.commit()
            cur.close()
            con.close()
        except:
            os.unlink(sqlite_file)
            raise

def main():
    #if not os.path.exists(titles_file) or not os.path.exists(references_file):
    #    parse_xml()
    #    save_json()
    if not os.path.exists(sqlite_file):
        parse_xml()
        save_sqlite()

if __name__ == "__main__":
    main()
