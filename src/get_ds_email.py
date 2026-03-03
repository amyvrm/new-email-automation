import requests
import os
from mail_common import MailCommonCode


class GenerateDSEmail(MailCommonCode):
    def __init__(self, dsru_version, issued_date, prev_dsru, dsru_mail, url, jfrog_token):
        MailCommonCode.__init__(self, dsru_version, issued_date, dsru_mail, url=url)
        print("####### Caling DS Mail #######")
        self.token = jfrog_token
        self.json_file_path = url
        self.src_pkg_json = self.get_json_file(dsru_version)
        self.prev_src_pkg_json = self.get_json_file(prev_dsru)
        self.get_deleted_rule()
        self.mail_id = "PSCInternal2; allofexternalrulesnotification"
        self.title = "Deep Security and Cloud One Workload Security"
        self.id = "DSRU"

    # this helps to load the json file from nexus to variable
    def get_json_file(self, dsru_version):
        path = os.path.join(self.json_file_path, dsru_version)
        url = os.path.join(path, "{}.json".format(dsru_version))
        print("# dsru_file: {}".format(url))
        return requests.get(url, headers={'Authorization': 'Bearer '+self.token}).json()

    # this is main method to generate ds mail
    def geneare_ds_mail(self, dsru_flag):
        self.create_ips_im_li_rule_info(dsru_flag)
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
