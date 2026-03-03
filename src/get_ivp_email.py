import requests
import os
from mail_common import MailCommonCode


class GenerateIVPEmail(MailCommonCode):
    def __init__(self, dsru_version, issued_date, prev_dsru, dsru_mail, url, ivp_high, jfrog_token):
        MailCommonCode.__init__(self, dsru_version, issued_date, dsru_mail, url=url)
        print("####### Caling IVP Mail #######")
        self.token = jfrog_token
        self.json_file_path = url
        self.src_pkg_json = self.get_json_file(dsru_version)
        self.prev_src_pkg_json = self.get_json_file(prev_dsru)
        self.get_deleted_rule()
        self.mail_id = "alloftrenddslabsvulprotection@dl.trendmicro.com; alloftrendworryfreenotify@dl.trendmicro.com; AllofPHDDIEngineers@dl.trendmicro.com"
        self.title = "Trend Micro Apex One Integrated Vulnerability Protection (iVP)"
        self.id = "TM-iVP"
        self.high_content = ivp_high

    # this helps to load the json file from nexus to variable
    def get_json_file(self, dsru_version):
        path = os.path.join(self.json_file_path, dsru_version)
        url = os.path.join(path, "iVPSecurityUpdate{}.json".format(dsru_version.replace("-", "")))
        print("# dsru_file: {}".format(url))
        return requests.get(url, headers={'Authorization': 'Bearer '+self.token}).json()

    # this is main method to generate ivp mail
    def geneare_ivp_mail(self, dsru_flag):
        self.create_ips_im_li_rule_info(dsru_flag, ivp=True)
        self.create_footer()

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
