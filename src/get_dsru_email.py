import requests
import os
from mail_common import MailCommonCode
from create_table_jira import CreateTableJira
import requests
import time
import datetime
import json

# it inherits the MailCommonCode code class which as all method needed in all the classes
class GenerateDSRUEmail(MailCommonCode):
    def __init__(self, dsru_version, issued_date, prev_dsru, dsru_mail, jira_cred, url, dsru_high,ms_table,
                 adobe_table, jfrog_token, teams_msg):
        # initialising the MailCommonCode class
        MailCommonCode.__init__(self, dsru_version, issued_date, dsru_mail, url)
        print("####### Caling DSRU Mail #######")
        # Nexus credential
        self.token = jfrog_token
        # Jira credential
        self.jira_cred = jira_cred
        self.json_file_path = url
        # loading supplied dsru version, json file
        self.src_pkg_json = self.get_json_file(dsru_version)
        # loading previous version of supplied dsru version, json file
        self.prev_src_pkg_json = self.get_json_file(prev_dsru)
        self.get_deleted_rule()
        self.ms_table = ms_table
        self.adobe_table = adobe_table
        self.mail_id = "AllofTrendDSSecurityUpdateNotification; AllofTrendDSDevOps; " \
                       "alloftrenddslabsvulprotection@dl.trendmicro.com; AllofPHDDIEngineers@dl.trendmicro.com"
        self.title = "Deep Security and Cloud One Workload Security"
        self.id = "DSRU"
        self.high_content = dsru_high
        self.teams_msg = teams_msg
        self.fields = []
        self.slack_fields = []

    # this helps to load the json file from nexus to variable
    def get_json_file(self, dsru_version):
        path = os.path.join(self.json_file_path, dsru_version)
        url = os.path.join(path, "{}.json".format(dsru_version))
        print("# dsru_file: {}".format(url))
        return requests.get(url, headers={'Authorization': 'Bearer '+self.token}).json()

    # this is main method to generate dsru mail
    def geneare_dsru_mail(self, dsru_flag, ms_flag, adobe_flag, bulletin_id):
        self.create_ips_im_li_rule_info(dsru_flag)
        status = False
        if ms_flag == 'true' or adobe_flag == 'true':
            # this jira class will be used to do query in Jira portal
            table = CreateTableJira(self.issued_date, self.ms_table, self.adobe_table, self.jira_cred,
                                    self.ips_new_rule, self.ips_updated_rule, bulletin_id)
            # check and append microsoft table
            if ms_flag == 'true':
                ms_res, ms_query = table.create_table("MS")
                self.teams_msg["ms_flag"] = True
                self.teams_msg["ms_res"] = int(ms_res)
                self.teams_msg["ms_query"] = ms_query
                self.format_table("Microsoft", self.ms_table)
            # check and append adobe table
            if adobe_flag == 'true':
                adobe_res, adobe_query = table.create_table("ADOBE")
                self.teams_msg["adobe_flag"] = True
                self.teams_msg["adobe_res"] = int(adobe_res)
                self.teams_msg["adobe_query"] = adobe_query
                self.format_table("Adobe", self.adobe_table)

            status = True
        # add footer
        self.create_footer()

        return status

    def get_deleted_rule(self):
        del_parent, del_child = 'DeleteTargets', 'DeleteTarget'

        try:
            for r in self.src_pkg_json[del_parent][del_child]:
                found = False
                for r1 in self.prev_src_pkg_json[del_parent][del_child]:
                    if r == r1:
                        found = True
                        break
                if not found:
                    if not ('Metadata' in r['ClassName']):
                        self.deleted_rules.append(r)
        except Exception:
            print("No Deleted rule found")
    def get_portlist(self, new, updated):
        # This method updated the new and updated dictionary and return the length
        iden1, iden2 = "PortLists", "PortList"
        if self.src_pkg_json[iden1]:
            for item in self.src_pkg_json[iden1][iden2]:
                item_issued_date = time.strftime('%Y-%m-%d', time.gmtime(int(item["Issued"]) / 1000))
                if item_issued_date == self.issued_date:
                    # check and update new rule dictionary and updated dictionary
                    if item["Version"] == "1":
                        new.update({item["TBUID"]: {
                            "name": item["Name"],
                            "added": item["Items"],
                            "removed": ""
                        }})
                    else:
                        prev = list(filter(lambda x: x["TBUID"] == item["TBUID"], self.prev_src_pkg_json[iden1][iden2]))
                        if len(prev) == 0:
                            prev = {"Items": ""}
                        else:
                            prev = prev[0]
                        added = ",".join(list(set((item["Items"] or "").split(",")) - set((prev["Items"] or "").split(","))))
                        removed = ",".join(list(set((prev["Items"] or "").split(",")) - set((item["Items"] or "").split(","))))
                        if added != "" or removed != "":
                            updated.update({item["TBUID"]: {
                                "name": item["Name"],
                                "added": added,
                                "removed": removed
                            }})
        return len(new.keys()), len(updated.keys())

    def get_apptype(self, new, updated):
        # This method updated the new and updated dictionary and return the length
        iden1, iden2 = "ConnectionTypes", "ConnectionType"
        if self.src_pkg_json[iden1]:
            for item in self.src_pkg_json[iden1][iden2]:
                item_issued_date = time.strftime('%Y-%m-%d', time.gmtime(int(item["Issued"]) / 1000))
                if item_issued_date == self.issued_date:
                    # check and update new rule dictionary and updated dictionary
                    if item["Version"] == "1":
                        new.update({item["TBUID"]: {
                            "name": item["Name"],
                            "added": item["Ports"],
                            "removed": ""
                        }})
                    else:
                        prev = list(filter(lambda x: x["TBUID"] == item["TBUID"], self.prev_src_pkg_json[iden1][iden2]))
                        if len(prev) == 0:
                            prev = {"Ports": ""}
                        else:
                            prev = prev[0]
                        added = ",".join(list(set((item["Ports"] or "").split(",")) - set((prev["Ports"] or "").split(","))))
                        removed = ",".join(list(set((prev["Ports"] or "").split(",")) - set((item["Ports"] or "").split(","))))
                        if added != "" or removed != "":
                            updated.update({item["TBUID"]: {
                                "name": item["Name"],
                                "added": added,
                                "removed": removed
                            }})
        return len(new.keys()), len(updated.keys())

    def get_reco(self, new, updated):
        # This method updated the new and updated dictionary and return the length
        iden1, iden2 = "DetectionRules", "DetectionRule"
        if self.src_pkg_json[iden1]:
            for item in self.src_pkg_json[iden1][iden2]:
                item_issued_date = time.strftime('%Y-%m-%d', time.gmtime(int(item["Issued"]) / 1000))
                if item_issued_date == self.issued_date:
                    # check and update new rule dictionary and updated dictionary
                    if item["Version"] == "1":
                        m1, t1 = self.tbuid2name(item["DetRuleTarget"])
                        new.update({item["TBUID"]: {
                            "name": item["Name"],
                            "added": t1,
                            "removed": "",
                            "mode": m1
                        }})
                    else:
                        prev = list(filter(lambda x: x["TBUID"] == item["TBUID"], self.prev_src_pkg_json[iden1][iden2]))
                        if len(prev) == 0:
                            prev = {"DetRuleTarget": ""}
                        else:
                            prev = prev[0]
                        if not "DetRuleTarget" in prev:
                            prev["DetRuleTarget"] = ""
                        m1, t1 = self.tbuid2name(item["DetRuleTarget"]) if item["DetRuleTarget"] != prev["DetRuleTarget"] else ("", "")
                        m2, t2 = self.tbuid2name(prev["DetRuleTarget"]) if item["DetRuleTarget"] != prev["DetRuleTarget"] else ("", "")
                        updated.update({item["TBUID"]: {
                            "name": item["Name"],
                            "added": t1,
                            "removed": t2,
                            "mode": m1
                        }})
        return len(new.keys()), len(updated.keys())

    def tbuid2name(self, tbuid):
        for mode in list(self.parse_json.keys()):
            iden0, iden1, iden2 = self.parse_json[mode]
            if self.src_pkg_json[iden1]:
                for item in self.src_pkg_json[iden1][iden2]:
                    title = ""
                    if "TBUID" in item:
                        if item["TBUID"] == tbuid:
                            if "Identifier" in item:
                                title += item["Identifier"] + " - "
                            if "Name" in item:
                                title += item["Name"]
                            return (mode, title)
        return (None, None)

    def apptype_port_rule_detail(self, data, isApp = True, isNew = True):
        # process the updated rule information mail draft
        header = "Application Types" if isApp else "Port Lists"
        rule_info = self.content_formatter("-", ("New " if isNew else "Updated ") + header)
        rule_info += "<ul>\n"
        if len(data) == 0:
            return "<ul>\n<li>There are no {} {} in this Security Update.</li>\n</ul>\n".format(("new" if isNew else "updated"), header)

        for item in data.values():
            rule_info += "\n<li><h5>{}</h5></li>\n<ul>\n".format(item["name"])
            rule_info += "\n<li>Added: {}</li>\n".format(item["added"]) if item["added"] != "" else ""
            rule_info += "\n<li>Removed: {}</li>\n".format(item["removed"]) if item["removed"] != "" else ""
            rule_info += "</ul>\n"
        rule_info += "</ul><br>\n"
        return rule_info

    def reco_rule_detail(self, isNew = True, isIPS = True, isLI = False):
        # Uncomment if no need reco
        return ""
        # process the updated rule information mail draft
        data = self.reco_new_rule if isNew else self.reco_updated_rule
        header = "Recommendation"
        rule_info = self.content_formatter("-", "Rules with " + ("new " if isNew else "updated ") + header)
        if len(data) == 0:
            return rule_info + "<ul>\n<li>There are no {} {} in this Security Update.</li>\n</ul>\n".format(("new" if isNew else "updated"), header)

        rule_info += "<ul>\n"
        check = False
        rset = set(map(lambda x: x["added"], filter(lambda x: x["mode"] == ("ips" if isIPS else ("li" if isLI else "im")), data.values())))
        rset.discard("")
        for item in rset:
            rule_info += "\n<li><h5>{}</h5></li>\n".format(item)
        rule_info += "</ul><br>\n"
        return rule_info if len(rset) != 0 else ""


if __name__ == "__main__":
    pass
