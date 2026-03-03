import datetime
import requests


class CreateTableJira(object):
    def __init__(self, issue_date, ms_table, adobe_adobe, jira_cred, new_rule, updated_rule, bulletin_id):
        self.ms_table = ms_table
        self.adobe_table = adobe_adobe
        self.jira_cred = jira_cred
        self.date_list = issue_date.split("-")
        self.release_month = datetime.date(int(self.date_list[0]), int(self.date_list[1]),
                                           int(self.date_list[2])).strftime('%B')
        self.new_rule = new_rule
        self.updated_rule = updated_rule
        self.bulletin_id = bulletin_id
        self.compatibility = "Y"

    def create_table(self, table_name):
        # For MS table
        # project=VULTX AND (status=Issued or "Issued Once"=Yes) AND type="DSLabs Filter" AND labels=MAPP_MS_July_2020
        # For Adobe table
        #project=VULTX AND (status=Issued or "Issued Once"=Yes) AND type="DSLabs Filter" AND labels=MAPP_ADOBE_July_2020
        # sprint = "\"Pinak-DSRU-{}/{}/{}\"".format(self.date_list[1], self.date_list[-1], self.date_list[0])

        filter = "MAPP_{}_{}_{}".format(table_name, self.release_month, self.date_list[0])
        base_link = "https://jr.trendmicro.com:8443/rest/api/2/search?jql="
        # jira_req = "{}project=VULTX AND (status=Issued or \"Issued Once\" = Yes or status = \"QA Passed\") AND " \
        #            "type=\"DSLabs Filter\" AND labels={}".format(base_link, filter)
        jira_req = '{}project=VULTX AND (status=Issued or "Issued Once" = Yes or status = "QA Passed") AND ' \
                   'type="DSLabs Filter" AND labels={}'.format(base_link, filter)
        print("jira request: {}".format(jira_req))
        # res_json = requests.get(jira_req, auth=self.jira_cred).json()
        res = requests.get(jira_req, auth=self.jira_cred)
        print("res: {}".format(res.status_code))
        if res.status_code != 200:
            raise Exception("Exception!!! Jira query failed")
        res_json = res.json()
        print("Total: {}".format(res_json["total"]))

        if table_name == "MS":
            self.get_ms_table(res_json)
        elif table_name == "ADOBE":
            self.get_adobe_table(res_json, base_link)
        return res_json["total"], jira_req

    def get_ms_table(self, res_json):
        print("#Creating Ms table #")
        release_date = "{}-{}-{}".format(self.date_list[-1], self.release_month, self.date_list[0])
        table_data = []

        for rule in res_json["issues"]:
            iden = rule["fields"]["customfield_13922"]
            if iden in self.new_rule.keys() or iden in self.updated_rule.keys():
                table_data.append({
                                    'CVE': rule["fields"]["customfield_13702"],
                                    'Release Date': release_date,
                                    'Protection Compatibility': self.compatibility,
                                    'Rule Identifier': rule["fields"]["customfield_13922"],
                                    'Rule Name': rule["fields"]["summary"]
                                })
            else:
                print("### {} Rule identification not found in New / Updated Rule ###".format(iden))
        fields = ['CVE', 'Release Date', 'Protection Compatibility', 'Rule Identifier', 'Rule Name']
        self.generate_table_from_data(table_data, fields, self.ms_table)

    def get_adobe_table(self, res_json, base_link):
        print("#Creating Adobe table #")
        release_date = "{}-{}-{}".format(self.date_list[-1], self.release_month, self.date_list[0])
        table_data = []

        for rule in res_json["issues"]:
            cve_list = []
            for cause_by in rule["fields"]["issuelinks"]:
                try:
                    cve_list.append(cause_by["inwardIssue"]["key"])
                except Exception:
                    pass
            if cve_list:
                print("labels: {}, cves: {}".format(rule["fields"]["labels"], cve_list))
                for cve in cve_list:
                    cve_link = "{}project=VULTX AND id={}".format(base_link, cve)
                    print("Emerging thread link: {}".format(cve_link))
                    cve_josn = requests.get(cve_link, auth=self.jira_cred).json()
                    if [detail["fields"]["issuetype"]["name"] == "Emerging Threat" for detail in cve_josn["issues"]][0]:
                        cve_num = [cve["fields"]["customfield_13702"] for cve in cve_josn["issues"]]
                        for cve in cve_num:
                            iden = rule["fields"]["customfield_13922"]
                            if iden in self.new_rule.keys() or iden in self.updated_rule.keys():
                                table_data.append({
                                    'Bulletin ID': self.bulletin_id,
                                    'CVE': cve,
                                    'Release Date': release_date,
                                    'Protection Compatibility': self.compatibility,
                                    'Rule Identifier': rule["fields"]["customfield_13922"],
                                    'Rule Name': rule["fields"]["summary"]
                                })
                            else:
                                print("### {} Rule identification not found in New / Updated Rule ###".format(iden))

        fields = ['Bulletin ID', 'CVE', 'Release Date', 'Protection Compatibility', 'Rule Identifier', 'Rule Name']
        self.generate_table_from_data(table_data, fields, self.adobe_table)

    def generate_table_from_data(self, data, fields, file):
        print("Table dumped in file: {}".format(file))
        with open(file, "a") as fin:
            fin.write("\t\t<br>\n")
            fin.write("\t\t<div class=\"container\">\n")
            # fin.write("\t\t\t<h4>Coverage for {} Patch Tuesday - December 2020:</h4>\n".format(header))
            fin.write("\t\t\t<table border=\"6\" bordercolorlight=\"#b9dcff\" bordercolordark=\"#006fdd\">\n")
            fin.write("\t\t\t\t<thead>\n")
            for header in fields:
                fin.write("\t\t\t\t\t<th>{}</th>\n".format(header))
            fin.write("\t\t\t\t</thead>\n\t\t\t\t<tbody>\n")

            for rule in data:
                fin.write("\t\t\t\t\t<tr>\n")
                for key in fields:
                    print("# {} #".format(rule[key]))
                    fin.write("\t\t\t\t\t\t<td style=\"text-align:center\">{}</td>\n".format(rule[key]))
                fin.write("\t\t\t\t\t</tr>\n")

            fin.write("\t\t\t\t</tbody>\n\t\t\t</table>\n")
            fin.write("\t\t</div>\n")
