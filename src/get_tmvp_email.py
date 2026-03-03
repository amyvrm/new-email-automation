import requests
import os
from mail_common import MailCommonCode
from create_table_jira import CreateTableJira


class GenerateTMVPEmail(MailCommonCode):
    def __init__(self, dsru_version, issued_date, prev_dsru, dsru_mail, jira_cred, url, vp_high,
                 ms_table, adobe_table, jfrog_token, teams_msg):
        MailCommonCode.__init__(self, dsru_version, issued_date, dsru_mail, url)
        print("####### Caling TMVP Mail #######")
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
        self.mail_id = "AllofTrendDSSecurityUpdateNotification; AllofTrendIDFPatternUpdateNotification;" \
                       "alloftrenddslabsvulprotection@dl.trendmicro.com; AllofPHDDIEngineers@dl.trendmicro.com"
        self.title = "Trend Micro Vulnerability Protection"
        self.id = "TMVP"
        self.high_content = vp_high
        self.teams_msg = teams_msg
        self.fields = []

    # this helps to load the json file from nexus to variable
    def get_json_file(self, dsru_version):
        path = os.path.join(self.json_file_path, dsru_version)
        url = os.path.join(path, "IDFSecurityUpdate{}.json".format(dsru_version.replace("-", "")))
        print("# dsru_file: {}".format(url))
        return requests.get(url, headers={'Authorization': 'Bearer '+self.token}).json()

    # this is main method to generate tmvp mail
    def geneare_tmvp_mail(self, dsru_flag, ms_flag, adobe_flag, bulletin_id):
        self.create_ips_im_li_rule_info(dsru_flag, no_im_li=False)
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
        self.create_footer(msg="Note: IDF has been replaced by TMVP (Trend Micro Vulnerability Protection)")

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


if __name__ == "__main__":
    pass
