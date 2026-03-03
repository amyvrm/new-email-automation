import json
import base64
import os
import time
import xml.etree.ElementTree as ET
import re


def main():
    ivp_json = {}
    for filename in os.listdir("update-packages"):
        if os.path.splitext(filename)[-1] == ".json":
            ivpfilename = os.path.join("update-packages", filename)
            if re.search(("VP"), ivpfilename):
                with open(ivpfilename) as f:
                    ivp_json = json.load(f)

    for filename in os.listdir("update-packages"):
        if os.path.splitext(filename)[-1] == ".json":
            update_packages = os.path.join("update-packages", filename)
            if re.search("|".join(["iVP", "VP", "IDF"]), update_packages) is None:
                parse(update_packages, ivp_json)


def parse(update_package_loc, ivp_json):
    package_folder = os.path.dirname(update_package_loc)
    package_name = os.path.basename(update_package_loc).rsplit(".", 2)[0]
    with open(update_package_loc) as f:
        dsru_json = json.load(f)
    # To add ATT&CK coverage Details
    mitre_coverage = {}

    # Add Basic info to json
    mitre_coverage = basic_info(mitre_coverage, dsru_json)

    # Add intrusionPrevention Details
    mitre_coverage = intrusion_prevention_info(mitre_coverage, dsru_json,ivp_json)

    # Add integrityMonitoring Related Details
    if dsru_json['IntegrityRules'] is not None:
        mitre_coverage = integrity_monitoring_info(mitre_coverage, dsru_json)

    # Add logInspection Related Details
    if dsru_json['LogInspectionRules'] is not None:
        mitre_coverage = log_inspection_info(mitre_coverage, dsru_json)

    with open(os.path.join(package_folder, "mitre_coverage_" + package_name + ".json"), "w") as f:
        json.dump(mitre_coverage, f, indent=2)


def basic_info(mitre_coverage, dsru_json):
    mitre_coverage["version"] = "1.0"
    mitre_coverage["schemaVersion"] = "1.0"
    mitre_coverage["datePublished"] = date_converter(dsru_json['Info']['Available'])
    mitre_coverage["dsruVersion"] = dsru_json['Info']['Version']
    mitre_coverage["att&ckVersion"] = "10"
    return mitre_coverage


def intrusion_prevention_info(mitre_coverage, dsru_json,ivp_json):
    type = ["Smart", "Vulnerability", "Exploit", "Hidden", "Policy", "Info"]
    severity = ["Low", "Medium", "High", "Critical"]
    #Create list of Extract Identifier from ivp json
    iVP_identifiers= []
    for intrusionPreventionRule in ivp_json['PayloadFilter2s']['PayloadFilter2']:
        iVP_identifiers.append(intrusionPreventionRule['Identifier'])

    intrusion_prevention_data = {}
    intrusion_prevention_data_list = []
    for intrusionPreventionRule in dsru_json['PayloadFilter2s']['PayloadFilter2']:
        if intrusionPreventionRule['att&ckIDs'] != None:
            intrusion_prevention_data["identifier"] = intrusionPreventionRule['Identifier']
            intrusion_prevention_data["name"] = intrusionPreventionRule['Name']
            intrusion_prevention_data["description"] = intrusionPreventionRule['Description']
            intrusion_prevention_data["applicationType"] = find_application_type(
                intrusionPreventionRule['ConnectionTypeTBUID'], dsru_json)
            intrusion_prevention_data["type"] = type[
                int(intrusionPreventionRule['Type']) - 1]  # Converting to match the json schema  Value
            intrusion_prevention_data["severity"] = severity[int(intrusionPreventionRule['Severity']) - 1]
            intrusion_prevention_data["att&ckIDs"] = intrusionPreventionRule['att&ckIDs']  # Will fix it
            # intrusion_prevention_data["recommended"] = intrusionPreventionRule['AssignByDefault']  # Not Sure
            intrusion_prevention_data["firstIssued"] = date_converter(intrusionPreventionRule['FirstIssued'])
            intrusion_prevention_data["lastIssued"] = date_converter(intrusionPreventionRule['Issued'])
            intrusion_prevention_data["detectOnly"] = intrusionPreventionRule['Mode']  # Not Sure
            intrusion_prevention_data["requiresConfiguration"] = intrusionPreventionRule['RequiresConfiguration']
            if intrusionPreventionRule['Identifier'] in iVP_identifiers:
                intrusion_prevention_data["ivp"] = "True"
            else:
                intrusion_prevention_data["ivp"] = "false"
            # Copying the data to the list
            intrusion_prevention_data_list.append(intrusion_prevention_data.copy())

    mitre_coverage["intrusionPrevention"] = intrusion_prevention_data_list
    return mitre_coverage


def integrity_monitoring_info(mitre_coverage, dsru_json):
    integrity_monitoring_data = {}
    integrity_monitoring_data_list = []
    severity = ["Low", "Medium", "High", "Critical"]
    for IntegrityRule in dsru_json['IntegrityRules']['IntegrityRule']:
        if IntegrityRule['att&ckIDs'] != None:
            integrity_monitoring_data["identifier"] = IntegrityRule['Identifier']
            integrity_monitoring_data["name"] = IntegrityRule['Name']
            integrity_monitoring_data["description"] = IntegrityRule['Description']
            integrity_monitoring_data["platform"] = find_IR_platform(IntegrityRule['Name']) #Win Lin TMTR App
            integrity_monitoring_data["severity"] = severity[int(IntegrityRule['Severity']) - 1]
            integrity_monitoring_data["att&ckIDs"] = IntegrityRule['att&ckIDs']
            # integrity_monitoring_data["recommended"] = IntegrityRule['AssignByDefault'] # Not Sure
            integrity_monitoring_data["firstIssued"] = date_converter(IntegrityRule['FirstIssued'])
            integrity_monitoring_data["lastIssued"] = date_converter(IntegrityRule['Issued'])
            integrity_monitoring_data["requiresConfiguration"] = IntegrityRule['RequiresConfiguration']

            # Copying the data to the list
            integrity_monitoring_data_list.append(integrity_monitoring_data.copy())

    mitre_coverage["integrityMonitoring"] = integrity_monitoring_data_list

    return mitre_coverage


def log_inspection_info(mitre_coverage, dsru_json):
    log_inspection_data = {}
    log_inspection_data_list = []
    for LogInspectionRule in dsru_json['LogInspectionRules']['LogInspectionRule']:
        log_inspection_data["identifier"] = LogInspectionRule['Identifier']
        log_inspection_data["name"] = LogInspectionRule['Name']
        log_inspection_data["description"] = LogInspectionRule['Description']
        log_inspection_data["ruleids"] = find_LI_ruletag_details(LogInspectionRule['GDL'])
        # log_inspection_data["recommended"] = IntegrityRule['Description']
        log_inspection_data["firstIssued"] = LogInspectionRule['FirstIssued']
        log_inspection_data["lastIssued"] = LogInspectionRule['Issued']
        log_inspection_data["requiresConfiguration"] = LogInspectionRule['RequiresConfiguration']

        if log_inspection_data["ruleids"] != None:
            # Copying the data to the list
            log_inspection_data_list.append(log_inspection_data.copy())

    mitre_coverage["logInspection"] = log_inspection_data_list

    return mitre_coverage

def find_IR_platform(Name):
    platform = re.findall("|".join( ["TMTR", "Microsoft Windows", "Application", "Linux/Unix"]),Name)
    if platform:
        return platform[0]
    else:
        return None

def find_LI_ruletag_details(GDL):
    if (GDL != None):
        validGdlXml = "<data>" + base64.b64decode(GDL).decode() + "</data>"
        # print(validGdlXml)
        obj = ET.fromstring(validGdlXml)
        ruleids = {}
        ruleids_list = []
        enterpriseTechniques = []
        for elem in obj.iter('Row'):
            for row in elem.iter('Control'):
                if row.attrib["type"] == "label":
                    enterpriseTechniques = re.findall("|".join(
                        ["T[0-9][0-9][0-9][0-9][\.][0-9][0-9][0-9]\-[0-9][0-9][0-9]",
                         "T[0-9][0-9][0-9][0-9]\-[0-9][0-9][0-9][0-9]", "T[0-9][0-9][0-9][0-9][\.][0-9][0-9][0-9]",
                         "T[0-9][0-9][0-9][0-9]"]), row.attrib['text'])
                if row.attrib["type"] == "level":
                    ruleid = re.search("|".join(["[0-9][0-9][0-9][0-9][0-9]", "[0-9][0-9][0-9][0-9]"]),
                                       row.attrib['value'])
                    severityLI = row.attrib['default']
            if enterpriseTechniques:
                ruleids["ruleid"] = int(ruleid.group())
                ruleids["att&ckIDs"] = enterpriseTechniques
                ruleids["severityLI"] = int(severityLI)
                ruleids_list.append(ruleids.copy())
        if ruleids_list:
            return ruleids_list
        return None


def date_converter(epoc_time):
    # Python support Max length 10 for time function attribute, so we are converting it to 10 digit
    if epoc_time != None:
        return time.strftime('%Y-%m-%d ', time.localtime(int(epoc_time) / 1000))
    return None


def find_application_type(ConnectionTypeTBUID, dsru_json):
    for ConnectionType in dsru_json['ConnectionTypes']['ConnectionType']:
        if ConnectionType['TBUID'] == ConnectionTypeTBUID:
            return ConnectionType['Name']


if __name__ == '__main__':
    main()
