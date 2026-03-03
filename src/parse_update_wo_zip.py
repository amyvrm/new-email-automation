# Parses the information stored in the DSRU update packages

import os
import json
import hashlib
import xml.etree.ElementTree as ET
import sys
import re

def main():
    for filename in os.listdir(sys.argv[1]):
        if os.path.splitext(filename)[-1] == ".decrypted":
            parse(os.path.join(sys.argv[1], filename), sys.argv[2])

def parse(update_package_loc, folder_name):
    # Even though the extension is .decrypted, the files themselves are zipfiles which contain the xml data inside them
    print(update_package_loc)
    with open(update_package_loc, "r") as fout:
        # Update package has all the information stored under the VSU tag
        # The tags under it are XSD (b64 encoded schema definition), Info (version, date, if package is sample),
        #   PortLists (list of common ports and their corresponding programs), ConnectionTypes (list of connection protocols),
        #   the filters which are separated into groups depending on type, each with a corresponding meta
        #   (PayloadFilter2s, IntegrityRules, LogInspectionRules, and LogInspectionDecoders)
        #   DetectionRules, DetectionExpressions, RuleGroups, VDB and DeleteTargets
        package_xml = fout.read()

        try:
            package_root = ET.fromstring(package_xml)
        except Exception as e:
            ### Issue Exception xml.etree.ElementTree.ParseError: not well-formed (invalid token): line 2447, column 21 ###
            print("Exception!!! parsing xml file [{}]".format(e))

            from lxml import etree
            parser = etree.XMLParser(recover=True)
            # Turn it into a python unicode string - ignore errors, kick out bad unicode
            decoded = package_xml.decode('utf-8', errors='ignore')  # (type <unicode>)
            # turn it back into a string, using utf-8 encoding.
            goodXML = decoded.encode('utf-8')  # (type <str>)
            package_root = etree.fromstring(goodXML, parser=parser)

        # List of fields that should be included as hash-only
        # NOTE: If you want all information to be uploaded, including encoded b64 rule data, use the top hash line instead
        #   This generally shouldn't be done, since it will include sensitive information, so use at your own risk
        # hash = []
        hash = ["XSD", "EngineXML", "RuleXML", "FileXML", "DecoderXML", "DetectionRuleXML", "DetectionExpressionXML", "GDL", "IconData"]

        package_name = os.path.basename(update_package_loc).rsplit(".", 2)[0]
        package_info = collect_package_info(package_root, hash)

        for intrusionPreventionRule in package_info['PayloadFilter2s']['PayloadFilter2']:
            if intrusionPreventionRule['Name'] is not None:
                enterpriseTechniques = re.findall("|".join(["T[0-9][0-9][0-9][0-9][\.][0-9][0-9][0-9]\-[0-9][0-9][0-9]",
                                                            "T[0-9][0-9][0-9][0-9]\-[0-9][0-9][0-9][0-9]",
                                                            "T[0-9][0-9][0-9][0-9][\.][0-9][0-9][0-9]",
                                                            "T[0-9][0-9][0-9][0-9]"]), intrusionPreventionRule['Name'])  # Finding Techniques
                if len(enterpriseTechniques) != 0:
                    intrusionPreventionRule["att&ckIDs"] = list(set(enterpriseTechniques))  # removing common Techniques
                else:
                    intrusionPreventionRule["att&ckIDs"] = None

        with open(os.path.join(folder_name, package_name + ".json"), "w") as f:
            json.dump(package_info, f, indent=2)


# We do know the structure of the XML file ahead of time, but to write specific parsing code would be quite lengthy
# Hence, we just recursively crawl the XML tree to collect the data
# Any tags that are part of "hash" are not directly added to the output; instead, their SHA-256 hash is added instead
def collect_package_info(xml_root, hash):
    package_info = {}
    for section in xml_root:
        if section.tag in hash:
            hashed = ""
            if section.text:
                hashed = hashlib.sha256(section.text.encode("utf-8")).hexdigest()
            package_info[f"{section.tag}-hash"] = hashed
        else:
            section_info = collect_package_info(section, hash)
            for attrib in section.attrib:  # Some of the XML tags also have attributes attached to them
                if not section_info:  # Some tags have nothing but attributes, and so return null above
                    section_info = {}
                section_info[attrib] = section.attrib[attrib]
            if section.tag not in package_info:
                package_info[section.tag] = section_info
            else:
                # We don't know ahead of time whether or not a given section is a single element or is a list
                # We assume it is single to begin with, and if we see it twice we convert to a list
                if not isinstance(package_info[section.tag], list):
                    package_info[section.tag] = [package_info[section.tag]]
                package_info[section.tag].append(section_info)
    if not package_info:  # We have reached the bottom of the XML tree
        return xml_root.text
    return package_info

if __name__ == '__main__':
    main()
