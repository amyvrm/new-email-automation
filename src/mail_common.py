import requests
import time
import datetime
import json


class MailCommonCode:
    def __init__(self, dsru_version, issued_date, dsru_mail, url=None):
        # initializing the MailCommonCode variables
        self.dsru_version = dsru_version
        self.issued_date = issued_date
        self.dsru_mail = dsru_mail
        self.json_file_path = url
        self.parse_json = {
                            "ips": ("Intrusion Prevention Rules", "PayloadFilter2s", "PayloadFilter2"),
                            "im": ("Integrity Monitoring Rules", "IntegrityRules", "IntegrityRule"),
                            "li": ("Log Inspection Rules", "LogInspectionRules", "LogInspectionRule")
                        }
        self.ips_new_rule, self.ips_updated_rule = {}, {}
        self.im_new_rule, self.im_updated_rule = {}, {}
        self.li_new_rule, self.li_updated_rule = {}, {}
        self.app_new_rule, self.app_updated_rule = {}, {}
        self.port_new_rule, self.port_updated_rule = {}, {}
        self.reco_new_rule, self.reco_updated_rule = {}, {}
        self.del_ips_rule, self.del_im_rule, self.del_li_rule = [], [], []
        self.deleted_rules = []

    @staticmethod
    def content_formatter(symbol, msg):
        for_design = symbol * 50
        return "<h5><br>{}<br>\n{}:<br>\n{}<br></h5>\n".format(for_design, msg, for_design)

    def create_html_header(self):
        # calculate the release date information
        self.date_list = self.issued_date.split("-")
        self.release_month = datetime.date(int(self.date_list[0]), int(self.date_list[1]),
                                           int(self.date_list[2])).strftime('%B')
        # created html header
        html_header = "<html><head>\n" \
                      "<link href=\"//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/css/bootstrap.min.css\" rel=\"stylesheet\" id=\"bootstrap-css\">\n" \
                      "<script src=\"//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/js/bootstrap.min.js\"></script>\n" \
                      "<script src=\"//code.jquery.com/jquery-1.11.1.min.js\"></script>\n" \
                      "<style>.tab {position:absolute;left:150px; }</style>\n" \
                      "</head>\n<body>\n"
        # drafting mail information
        html_header += "<p>{}<br>\n".format(self.mail_id)
        html_header += "Dear Customer,<br><br>\n"
        html_header += "Trend Micro has released Security Update {} for {}.".format(self.dsru_version, self.title)
        html_header += "<br><br>\n{} ID : {}<br><br>\n".format(self.id, self.dsru_version)
        html_header += "Release Date: {} {}, {}<br><br>\n".format(self.release_month, self.date_list[2],
                                                                  self.date_list[0])
        html_header += MailCommonCode.content_formatter("=", "Contents of Update {}".format(self.dsru_version))
        html_header += "<h5>Table of Contents<br>{}</h5>".format("-" * 50)
        return html_header

    def create_ips_im_li_rule_info(self, high_flag, ivp=False, no_im_li=True):
        # Fetch the summary
        summary_info = self.create_content_summary(ivp)
        if not summary_info:
            self.date_list = self.issued_date.split("-")
            self.release_month = datetime.date(int(self.date_list[0]), int(self.date_list[1]),
                                               int(self.date_list[2])).strftime('%B')
            return False
        # draft the mail - header, summary, highlight, rule information
        with open(self.dsru_mail, "a") as fin:
            fin.write(self.create_html_header())
            fin.write(summary_info)
            self.write_highlights(high_flag, fin)
            # Mail type
            if ivp:
                fin.write(self.content_formatter("=", "Trend Micro Apex One Integrated Vulnerability Protection "
                                                      "(iVP)Rules"))
            else:
                fin.write(self.content_formatter("=", "Intrusion Prevention Rules"))
            ips_reco_update = self.reco_rule_detail(False, True, False)
            if ips_reco_update != "" or len(self.ips_new_rule) > 0 or len(self.ips_updated_rule) > 0 or len(self.app_new_rule) > 0 or len(self.app_updated_rule) > 0 or len(self.port_new_rule) > 0 or len(self.port_updated_rule) > 0 :
                fin.write(self.new_ips_rule_detail(ivp))
                fin.write(self.updated_ips_rule_detail(ivp))
                #fin.write(self.apptype_port_rule_detail(self.app_new_rule, True, True))
                fin.write(self.apptype_port_rule_detail(self.app_updated_rule, True, False))
                #fin.write(self.apptype_port_rule_detail(self.port_new_rule, False, True))
                fin.write(self.apptype_port_rule_detail(self.port_updated_rule, False, False))
                fin.write(ips_reco_update)

            else:
                fin.write("<ul>\n<li>There are no new or updated Intrusion Prevention Rules in this Security "
                          "Update.</li>\n</ul>\n")
            del_rule, msg = self.format_deleted_rules(self.del_ips_rule)
            if del_rule:
                fin.write(msg)
            if not ivp and no_im_li:
                fin.write(self.create_rule_detail(self.parse_json["im"], self.im_new_rule, self.im_updated_rule))
                fin.write(self.create_rule_detail(self.parse_json["li"], self.li_new_rule, self.li_updated_rule))

    def write_highlights(self, high_flag, fin):
        # prepare draft
        if high_flag == 'true':
            print("highlight content: {}".format(self.high_content))
            fin.write(self.content_formatter("=", "Highlights"))
            fin.write("<div>\n<ul>\n")
            for line in self.high_content.split("\n"):
                if line:
                    fin.write("<li>{}</li>\n".format(line))
            fin.write("</ul>\n</div>\n")

    def create_content_summary(self, ivp):
        summary_info = ""

        # Get New or updated Intrusion Prevention Rules
        ips_new, ips_update = self.get_rules(self.parse_json["ips"], self.ips_new_rule, self.ips_updated_rule)
        # Get deleted rule list
        self.del_ips_rule = self.get_deleted_rule_info(self.parse_json["ips"])
        del_rule = len(self.del_ips_rule)
        print("IPS Stats: new - {}, updated - {}, Deleted - {}".format(ips_new, ips_update, del_rule))
        # if new or updated rule exist then update it into summary
        if ips_new or ips_update:
            summary_info += self.get_category_summary(self.parse_json["ips"][0], ips_new, ips_update, del_rule)
        # Check apptype, portlist, reco
        app_new, app_update = self.get_apptype(self.app_new_rule, self.app_updated_rule)
        port_new, port_update = self.get_portlist(self.port_new_rule, self.port_updated_rule)
        reco_new, reco_update = self.get_reco(self.reco_new_rule, self.reco_updated_rule)
        app_new = 0
        port_new = 0

        if app_new or app_update:
            t = self.get_category_summary("Application Types", app_new, app_update, 0, "Application Types", no_new = True)
            summary_info = summary_info[:summary_info.rindex("</ul>")-6] + t[t.index("<li>U"):]
        if port_new or port_update:
            t = self.get_category_summary("Port Lists", port_new, port_update, 0, "Port Lists", no_new = True)
            summary_info = summary_info[:summary_info.rindex("</ul>")-6] + t[t.index("<li>U"):]
        #if reco_new or reco_update:
        #    summary_info += self.get_category_summary("Recommendation Rules", reco_new, reco_update, 0)
        # check ivp mail creation
        if not ivp:
            # Get New or Updated Integrity Rules
            im_new, im_update = self.get_rules(self.parse_json["im"], self.im_new_rule, self.im_updated_rule)
            self.del_im_rule = self.get_deleted_rule_info(self.parse_json["im"])
            del_rule = len(self.del_im_rule)
            print("IM Stats: new - {}, updated - {}, Deleted - {}".format(im_new, im_update, del_rule))
            if im_new or im_update:
                summary_info += self.get_category_summary(self.parse_json["im"][0], im_new, im_update, del_rule)

            # Get New or Updated Log Inspection Rules
            li_new, li_update = self.get_rules(self.parse_json["li"], self.li_new_rule, self.li_updated_rule)
            self.del_li_rule = self.get_deleted_rule_info(self.parse_json["li"])
            del_rule = len(self.del_li_rule)
            print("LI Stats: new - {}, updated - {}, Deleted - {}".format(li_new, li_update, del_rule))
            if li_new or li_update:
                summary_info += self.get_category_summary(self.parse_json["li"][0], li_new, li_update, del_rule)
        # if not rule found then check and update the message
        if not summary_info:
            with open(self.dsru_mail, "w") as fin:
                fin.write("No items found")
            return False
        else:
            return summary_info

    def get_category_summary(self, parse_info, new, updated, del_rule, rtype = "Rules", no_new = False):
        # formatting the information html into unordered list and list list
        rule_summary = "<div>\n<ul>\n<li><h5>{}:</h5></li>\n".format(parse_info)
        rule_summary += "<ul>\n"
        rule_summary += "<li>New {}: {}</li>\n".format(rtype, new) if not no_new else ""
        rule_summary += "<li>Updated {}: {}</li>\n".format(rtype, updated)
        rule_summary += "<li>Deleted {}: {}</li>\n".format(rtype, del_rule) if del_rule > 0 else "\n"
        rule_summary += "</ul>\n</ul>\n</div>\n"
        return rule_summary

    def new_ips_rule_detail(self, ivp):
        # get metadata of ips rules
        self.type_meta_data = {
            "1": "Custom",
            "2": "Smart",
            "3": "Vulnerability",
            "4": "Exploit",
            "5": "Hidden",
            "6": "Policy",
            "7": "Info"
        }
        header = "Trend Micro Apex One Integrated Vulnerability Protection (iVP) Rules" if ivp else "Intrusion " \
                                                                                                     "Prevention Rules"
        # check new ips rule and format the message in case of no rule
        if len(self.ips_new_rule) == 0:
            return "<ul>\n<li>There are no new {} in this Security Update.</li>\n</ul>\n".format(header)
        print(self.ips_new_rule)
        rule_info = self.content_formatter("-", "New Rules")
        rule_info += "<ol>\n"

        for id in self.ips_new_rule.keys():
            # initializing the set for cves
            cves = set()
            cvss = ""
            # fetching VDB information to extract cvss score and cves
            for vdb_data in self.src_pkg_json["VDB"]["Vulnerability"]:
                filters = vdb_data["Filters"].split(",")
                for fid in filters:
                    if fid == self.ips_new_rule[id]["TBUID"]:
                        cvss = vdb_data["CVSS"]
                        try:
                            # print("# For {} VDB Link: [{}] #".format(id, vdb_data["Link"]))
                            if vdb_data["Link"]["type"] == "5":
                                cves.add("CVE-" + vdb_data["Link"]["id"])
                        except (TypeError, KeyError) as e:
                            # print("# Exception!!! id-{} vdb link id not found: {} #".format(id, e))
                            try:
                                for link in vdb_data["Link"]:
                                    if link["type"] == "5":
                                        cves.add("CVE-" + link["id"])
                            except KeyError as e:
                                # print("# Exception!!! id-{} vdb link not found: {} #".format(id, e))
                                pass

            print("### {}, cves-{}, cvss-{} ###".format(id, cves, cvss))
            if not cves:
                cves.add("NA")
            if not cvss:
                cvss = "Please enter cvss manually (Vdb: NA)"
                print("########### No CVSS found because didn't hit the VDB filters match for {} #########".format(id))
            # Get app type
            for conn_type in self.src_pkg_json["ConnectionTypes"]["ConnectionType"]:
                if conn_type["TBUID"] == self.ips_new_rule[id]["ConnectionTypeTBUID"]:
                    app_type = conn_type["Name"]
            # format the information of ips rules and metadata
            rule_info += "<li><h5>{} - {}</h5></li>\n".format(id, self.ips_new_rule[id]["Name"])
            rule_info += "<ul>\n<li>{}</li>\n".format(", ".join(str(cve) for cve in cves))
            def_mode = "Detect" if self.ips_new_rule[id]["Mode"] == "1" else "Prevent"
            rule_info += "<li>Default Mode: {}</li>\n".format(def_mode)
            rule_info += "<li>CVSS: {}</li>\n".format(cvss)
            rule_info += "<li>App Type: {}</li>\n".format(app_type)
            rule_info += "<li>Type: {}</li>\n".format(self.type_meta_data[self.ips_new_rule[id]["Type"]])
            if not ivp:
                req_conf = "No" if self.ips_new_rule[id]["RequiresConfiguration"] == 'false' else 'Yes'
                rule_info += "<li>RequiresConfiguration: {}</li>\n".format(req_conf)
                print("# Flags: {} #".format(self.ips_new_rule[id]["Flags"]))
                try:
                    # flag the Recommendation scan infromation
                    if "DISABLERECOMMENDATION" in self.ips_new_rule[id]["Flags"]:
                        rule_info += "<li>Excluded From Recommendation Scan</li>\n</ul>\n"
                    else:
                        rule_info += "<li>Included in Recommendation Scan</li>\n</ul>\n"
                except Exception as e:
                    print("Error!!! {}".format(e))
                    rule_info += "<li>Included in Recommendation Scan</li>\n</ul>\n"
        rule_info += "</ol>\n"
        return rule_info

    def updated_ips_rule_detail(self, ivp):
        # process the updated rule information mail draft
        header = "Trend Micro Apex One Integrated Vulnerability Protection (iVP) Rules" if ivp else "Intrusion " \
                                                                                                     "Prevention Rules"
        rule_info = self.content_formatter("-", "Updated Rules")
        rule_info += "<ul>\n"
        if len(self.ips_updated_rule) == 0:
            return "<ul>\n<li>There are no updated {} in this Security Update.</li>\n</ul>\n".format(header)
        self.get_all_update_meta_data()

        for meta, rule_list in self.meta_data.items():
            rule_info += "\n<li><h5>{}</h5></li>\n<ul>\n".format(meta)
            for rule in rule_list:
                rule_info += "\n<li>{}</li>\n".format(rule)
            rule_info += "</ul>\n"
        rule_info += "</ul><br>\n"
        rule_info += "- All Code Change rules enhanced for accuracy and/or performance based on latest threat " \
                     "information<br><br>\n"
        return rule_info

    def get_deleted_rule_info(self, keys):
        iden1, iden2 = keys[1], keys[2]
        rule_list = []

        for d_rule in self.deleted_rules:
            try:
                for rule in self.prev_src_pkg_json[iden1][iden2]:
                    if d_rule['TBUID'] == rule['TBUID']:
                        if rule["FirstIssued"] and rule["Issued"]:
                            rule_list.append([rule['Identifier'], rule['Name']])
            except TypeError as e:
                pass

        return rule_list

    def format_deleted_rules(self, rule_list):
        rule_info = self.content_formatter("-", "Deleted Rules")
        rule_info += "<ul>\n"

        if len(rule_list) > 0:
            for rule in rule_list:
                rule_info += "\n<li>{} - {}</li>\n".format(rule[0], rule[1])
            rule_info += "</ul><br>\n"
            return True, rule_info
        else:
            return False, ""

    def update_rule_name(self, ident, meta_data):
        try:
            self.meta_data[meta_data].append("{} - {}".format(ident, self.ips_updated_rule[ident]["Name"]))
        except Exception:
            self.meta_data[meta_data] = ["{} - {}".format(ident, self.ips_updated_rule[ident]["Name"])]

    def get_all_update_meta_data(self):
        print("# Check updated Rule #")
        self.meta_data = {}
        for ident in self.ips_updated_rule.keys():
            iden1, iden2 = self.parse_json["ips"][1], self.parse_json["ips"][2]
            # fetching reason of updated rule from previous version
            for rules in self.prev_src_pkg_json[iden1][iden2]:
                if ident == rules["Identifier"]:
                    meta_data_flag = False
                    # check change for detection mode to prevent mode and vise-versa
                    if self.ips_updated_rule[ident]["Mode"] != rules["Mode"]:
                        before_mode = "Detect-Only" if rules["Mode"] == "1" else "Prevent"
                        mode = "Detect-Only" if self.ips_updated_rule[ident]["Mode"] == "1" else "Prevent"
                        self.update_rule_name(ident, "{} changed to {}".format(before_mode, mode))
                        meta_data_flag = True

                    try:
                        # check for Code Change
                        if self.ips_updated_rule[ident]["RuleXML-hash"] != rules["RuleXML-hash"]:
                            self.update_rule_name(ident, "Code Change")
                            meta_data_flag = True
                    except KeyError as e:
                        print("# Exception!!! in Code Change: {} #".format(e))

                    try:
                        # check for Required Configuration change
                        if self.ips_updated_rule[ident]["RequiresConfiguration"] != rules["RequiresConfiguration"]:
                            self.update_rule_name(ident, "RequiresConfiguration Change")
                            meta_data_flag = True
                    except KeyError as e:
                        print("# Exception!!! in RequiresConfiguration: {} #".format(e))

                    disable_rec = "DISABLERECOMMENDATION"
                    new_scan = self.ips_updated_rule[ident]["Flags"]
                    print("# {} Recommendation Scan: New-{}, Old-{}#".format(ident, new_scan, rules["Flags"]))
                    # check for disabled recommendation scan
                    if new_scan and rules["Flags"]:
                        if (disable_rec in new_scan and disable_rec in rules["Flags"]) or \
                                (disable_rec not in new_scan and disable_rec not in rules["Flags"]):
                            print("# {} No change in Recommendation Scan #".format(ident))
                        else:
                            if disable_rec in self.ips_updated_rule[ident]["Flags"]:
                                self.update_rule_name(ident, "Changed from Included to Excluded in Recommendation Scan")
                            else:
                                self.update_rule_name(ident, "Changed from Excluded to Included in Recommendation Scan")
                            meta_data_flag = True
                    elif new_scan:
                        if disable_rec in self.ips_updated_rule[ident]["Flags"]:
                            self.update_rule_name(ident, "Changed from Included to Excluded in Recommendation Scan")
                            meta_data_flag = True
                    elif rules["Flags"]:
                        self.update_rule_name(ident, "Changed from Excluded to Included in Recommendation Scan")
                        meta_data_flag = True
                    else:
                        print("# {} No change in Recommendation Scan #".format(ident))

                    # Meta data change
                    if not meta_data_flag:
                        self.update_rule_name(ident, "Other Metadata change")

    def create_rule_detail(self, parse_json, new, updated):
        # formation rule information
        rule_info = ""
        rule_info += self.content_formatter("=", parse_json[0])
        new_rule = len(new) > 0
        updated_rule = len(updated) > 0
        reco_update = self.reco_rule_detail(False, False, parse_json[0] == "Log Inspection Rules")
        # No new or updated rule
        if not new_rule and not updated_rule and reco_update == "":
            rule_info += "<ul>\n<li>There are no new or updated {} in this Security Update.</li>\n</ul>\n".format(
                parse_json[0])
        # for new rule
        if new_rule:
            rule_info += self.content_formatter("-", "New Rules")
            rule_info += self.rule_detail(new)
        # for updated rule
        if updated_rule:
            rule_info += self.content_formatter("-", "Updated Rules")
            rule_info += self.rule_detail(updated)
            rule_info += "- All Code Change rules enhanced for accuracy and/or performance based on latest threat " \
                         "information<br><br>\n"
        # check and format Integrity Monitoring Rules
        if parse_json[0] == "Integrity Monitoring Rules":
            del_rule, msg = self.format_deleted_rules(self.del_im_rule)
            if del_rule:
                rule_info += msg
        # check and format Log Inspection Rules
        if parse_json[0] == "Log Inspection Rules":
            del_rule, msg = self.format_deleted_rules(self.del_li_rule)
            if del_rule:
                rule_info += msg

        rule_info += reco_update
        return rule_info

    def get_rules(self, json_info, new, updated):
        # This method updated the new and updated dictionary and return the length
        iden1, iden2 = json_info[1], json_info[2]
        if self.src_pkg_json[iden1]:
            for rules in self.src_pkg_json[iden1][iden2]:
                rules_issued_date = time.strftime('%Y-%m-%d', time.gmtime(int(rules["Issued"]) / 1000))
                if rules_issued_date == self.issued_date:
                    # check and update new rule dictionary and updated dictionary
                    if rules["Issued"] == rules["FirstIssued"]:
                        new.update({rules["Identifier"]: rules})
                    else:
                        updated.update({rules["Identifier"]: rules})
        return len(new.keys()), len(updated.keys())

    def rule_detail(self, rule_list):
        # This helps to format the rule detail
        format_msg = "<div>\n<ol>\n"
        for id in rule_list.keys():
            format_msg += "<li>{} - {}</li>\n".format(id, rule_list[id]["Name"])
        format_msg += "</ol>\n</div>\n"
        return format_msg

    def updated_rule_detail(self):
        # This helps to format the updated rule detail
        format_msg = self.content_formatter("-", "Updated Rules")
        format_msg += "<div><ol>"
        for id in self.updated_rule_list.keys():
            format_msg += "<li>{} - {}</li>\n".format(id, self.updated_rule_list[id]["Name"])
        format_msg += "</ol>\n</div>\n"
        format_msg += "<br>\n"
        format_msg += "- All Code Change rules enhanced for accuracy and/or performance based on latest threat information\n"
        return format_msg

    def create_footer(self, msg=False):
        # this creates a footer and dump into the respective class file
        with open(self.dsru_mail, "a") as fin:
            if msg:
                fin.write("<br>* {}".format(msg))
            fin.write("</body>\n</head></html>\n")

    def change_date_format(self):
        # release_date = "2020-02-11"
        # release_date1 = "02/11/2020"
        self.release_date = "{}/{}/{}".format(self.date_list[1], self.date_list[2], self.date_list[0])
        print("new release date: {}".format(self.release_date))

    def format_html_table(self, file_name):
        # This method helps to append the table such as microsoft and adobe in to mail draft
        with open(file_name, "r") as fout:
            table = fout.read()
            html_table = "<div class=\"container\"><div class=\"row\">"
            html_table += table
            html_table += "</div></div>"
            return html_table

    def format_table(self, header, file):
        with open(self.dsru_mail, "a") as fin:
            # MS table for DSRU
            fin.write("<br><h5><u>Coverage for {} Patch Tuesday - {} {}:</u></h5>".format(header, self.release_month,
                                                                                                 self.date_list[0]))
            fin.write(self.format_html_table(file))

    def send_teams_notification(self, webhook, jenkins_build, sub_title):
        # This created teams notification
        self.prepare_teams_data()
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "00ff00",
            "summary": "Email Auto V2",
            "sections":
                [
                    {
                        "activityTitle": "Email Auto V2 Pipeline",
                        "activitySubtitle": sub_title,
                        "activityImage": "https://teamsnodesample.azurewebsites.net/static/img/image5.png",
                        "facts": self.fields,
                        "markdown": True
                    },
                    {
                        'text': self.queries
                    }
                ],
            "potentialAction":
                [
                    {
                        "@type": "OpenUri",
                        "name": "View Jenkins Build",
                        "targets":
                            [
                                {
                                    "os": "default",
                                    "uri": jenkins_build
                                }
                            ]
                    }
                ]
        }

        headers = {'content-type': 'application/json'}
        requests.post(webhook, data=json.dumps(message), headers=headers)

    def prepare_teams_data(self):
        # preparing the teams message
        self.queries = ""
        if self.teams_msg["ms_flag"]:
            ms_msg = [
                {
                    "name": "Get MS Table",
                    "value": "Yes"
                },
                {
                    "name": "MS Rule Count",
                    "value": self.teams_msg["ms_res"]
                }
            ]
            self.fields.extend(ms_msg)
            self.queries += '<b>MS Table query:</b> <p>{}</p>'.format(self.teams_msg["ms_query"])
            # if self.teams_msg["adobe_flag"]:
            #     self.queries += "<br>"

        if self.teams_msg["adobe_flag"]:
            ms_msg = [
                {
                    "name": "Get Adobe Table",
                    "value": "Yes"
                },
                {
                    "name": "Adobe Rule Count",
                    "value": self.teams_msg["adobe_res"]
                }
            ]
            self.fields.extend(ms_msg)
            self.queries += '<br><b>Adobe Table query:</b> <p>{}</p>'.format(self.teams_msg["adobe_query"])
            self.queries += '<br><b>Note:</b> <p>Email Copy sent to User mail id</p>'

    def slack_post(self, webhook, jenkins_build, sub_title):
        self.prepare_slack_msg()

        message = {
                        "attachments": [
                            {
                                "fallback": "Email Automation V2 Pipeline",
                                "color": "#36a64f",
                                "pretext": "Email Automation V2 Pipeline Notification",
                                "title": "View Jenkins Build",
                                "title_link": jenkins_build,
                                "text": sub_title,
                                "fields": self.slack_fields,
                                "image_url": "http://my-website.com/path/to/image.jpg",
                                "thumb_url": "http://example.com/path/to/thumb.png",
                                "footer": "Slack API",
                                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                                "ts": 123456789
                            },
                            {
                                "color": "#439FE0",
                                "title": "Note: Email Copy sent to User mail id"
                            }
                        ]
                    }

        headers = {'content-type': 'application/json'}
        requests.post(webhook, data=json.dumps(message), headers=headers)

    def prepare_slack_msg(self):
        self.queries = ""
        if self.teams_msg["ms_flag"]:
            ms_msg = [
                {
                    "title": "Get MS Table",
                    "value": "Yes",
                    "short": "true"
                },
                {
                    "title": "MS Rule Count",
                    "value": self.teams_msg["ms_res"],
                    "short": "true"
                }
            ]
            self.slack_fields.extend(ms_msg)

        if self.teams_msg["adobe_flag"]:
            ms_msg = [
                        {
                            "title": "Get Adobe Table",
                            "value": "Yes",
                            "short": "true"
                        },
                        {
                            "title": "Adobe Rule Count",
                            "value": self.teams_msg["adobe_res"],
                            "short": "true"
                        }
            ]

            self.slack_fields.extend(ms_msg)

        if self.teams_msg["ms_flag"]:
            ms_msg = [
                {
                    "title": "MS Table Query",
                    "value": "{}".format(self.teams_msg["ms_query"]),
                    "short": "false"
                }
            ]
            self.slack_fields.extend(ms_msg)

        if self.teams_msg["adobe_flag"]:
            ms_msg = [
                {
                    "title": "Adobe Table Query",
                    "value": "{}".format(self.teams_msg["adobe_query"]),
                    "short": "false"
                }
            ]
            self.slack_fields.extend(ms_msg)

    def get_portlist(self, new, updated):
        return 0,0

    def get_apptype(self, new, updated):
        return 0,0

    def get_reco(self, new, updated):
        return 0,0

    def tbuid2name(self, tbuid):
        return (None, None)

    def apptype_port_rule_detail(self, data, isApp = True, isNew = True):
        return ""

    def reco_rule_detail(self, isNew = True, isIPS = True, isLI = False):
        return ""


if __name__ == "__main__":
    pass
    # formatting rule info
    # create_ips_im_li_rule_info(args.dsru_flag, args.dsru_high)
