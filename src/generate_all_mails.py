import argparse
import glob
import os
from get_dsru_email import GenerateDSRUEmail
from get_tmvp_email import GenerateTMVPEmail
from get_ivp_email import GenerateIVPEmail
from get_vp_email import GenerateVPEmail
from get_ds_email import GenerateDSEmail

# This method cleans environment
def clean():
    print('******* clean all html files ********')
    filelist = glob.glob(os.path.join(os.getcwd(), "*.html"))
    for f in filelist:
        print('- Removing: {}'.format(f))
        os.remove(f)

if __name__ == "__main__":
    # object of DSRU email generation
    parser = argparse.ArgumentParser(description='Please provide deatil to generate mail')
    parser.add_argument('--dsru_ver', type=str, help="DSRU Version detail")
    parser.add_argument('--prev_dsru_ver', type=str, help="Last DSRU Version detail for updated rule")
    parser.add_argument('--issue_Date', type=str, help="Issued date detail")
    parser.add_argument('--dsru_flag', type=str, help="Get flag to decide whether highlights will be part of email")
    parser.add_argument('--dsru_high', type=str, help="Get DSRU highlights content for email")
    # Phasing out IDF/VP Package.
    # parser.add_argument('--idf_flag', type=str, help="Flag to whether add TMVP highlights")
    # parser.add_argument('--idf_high', type=str, help="TMVP highlights content for email")
    parser.add_argument('--ivp_flag', type=str, help="Add IVP highlights from DSRU Email")
    parser.add_argument('--ivp_high', type=str, help="Get IVP highlights content for email")
    parser.add_argument('--ms_flag', type=str, help="Add or Remove MS table from DSRU Email")
    parser.add_argument('--adobe_flag', type=str, help="Add or Remove Adobe table from DSRU Email")
    parser.add_argument('--jira_uname', type=str, help="Jira username")
    parser.add_argument('--jira_pwd', type=str, help="Jira password")
    parser.add_argument('--url', type=str, help="decrypted dsru package base path")
    parser.add_argument('--bulletin_id', type=str, help="Bulletin id")
    parser.add_argument('--jfrog_token', type=str, help="JFrog token")
    parser.add_argument('--webhook', type=str, help="Teams webhook")
    parser.add_argument('--jenkins_build', type=str, help="Jenkins build url")
    parser.add_argument('--slack_webhook', type=str, help="Slack webhook")

    args = parser.parse_args()
    jira_cred = (args.jira_uname, args.jira_pwd)

    dsru_mail = "dsru_mail.html"
    # Phasing out IDF/VP Package.
    # tmvp_mail = "tmvp_mail.html"
    # vp_mail = "vp_mail.html"
    ivp_mail = "ivp_mail.html"
    psp_dsru_mail = "psp_dsru_mail.html"

    ms_table = "ms_table.html"
    adobe_table = "adobe_table.html"
    tmvp_ms_table = "tmvp_ms_table.html"
    tmvp_adobe_table = "tmvp_adobe_table.html"
    clean()

    teams_msg = {
        "ms_flag": False,
        "adobe_flag": False,
        "ms_res": 0,
        "ms_query": 0,
        "adobe_res": 0,
        "adobe_query": 0
    }

    # dsru issued mail
    dsru_obj = GenerateDSRUEmail(args.dsru_ver, args.issue_Date, args.prev_dsru_ver, dsru_mail, jira_cred, args.url,
                                 args.dsru_high, ms_table, adobe_table, args.jfrog_token, teams_msg)
    status = dsru_obj.geneare_dsru_mail(args.dsru_flag, args.ms_flag, args.adobe_flag, args.bulletin_id)
    if status:
        dsru_obj.send_teams_notification(args.webhook, args.jenkins_build, "DSRU Email Query status")
        dsru_obj.slack_post(args.slack_webhook, args.jenkins_build, "DSRU Email Query status")
    """
    Phasing out IDF/VP Package.
    # tmvp / idf issued mail
    tmvp_obj = GenerateTMVPEmail(args.dsru_ver, args.issue_Date, args.prev_dsru_ver, tmvp_mail, jira_cred, args.url,
                                 args.idf_high, tmvp_ms_table, tmvp_adobe_table, args.jfrog_token, teams_msg)
    if tmvp_obj.geneare_tmvp_mail(args.idf_flag, args.ms_flag, args.adobe_flag, args.bulletin_id):
        if not status:
            tmvp_obj.send_teams_notification(args.webhook, args.jenkins_build, "TMVP Email Query status")
            tmvp_obj.slack_post(args.slack_webhook, args.jenkins_build, "TMVP Email Query status")
    # tmvp mail
    vp_obj = GenerateVPEmail(args.dsru_ver, args.issue_Date, args.prev_dsru_ver, vp_mail, args.url, args.jfrog_token)
    vp_obj.geneare_vp_mail('false')
    """
    # ivp mail
    ivp_obj = GenerateIVPEmail(args.dsru_ver, args.issue_Date, args.prev_dsru_ver, ivp_mail, args.url, args.ivp_high, args.jfrog_token)
    ivp_obj.geneare_ivp_mail(args.ivp_flag)

    # dsru mail
    ds_obj = GenerateDSEmail(args.dsru_ver, args.issue_Date, args.prev_dsru_ver, psp_dsru_mail, args.url, args.jfrog_token)
    ds_obj.geneare_ds_mail('false')
