# Sends slack notifications on the status of the job

import json
import argparse
import requests

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", action="store", type=str, help="Build User")
    parser.add_argument("-s", "--status", action="store", type=str, help="SUCCESS or FAILURE")
    parser.add_argument("-ju", "--jfrog_url", action="store", type=str, help="JFrog upload url")
    parser.add_argument("-b", "--build_url", action="store", help="Jenkins Build URL")
    parser.add_argument("-w", "--webhook_url", action="store", help="Slack Webhook URL")
    parser.add_argument("-c", "--channel", action="store", help="Channel ID used for searching user IDs")
    parser.add_argument("-a", "--auth_token", action="store", help="Authorization token to perform ID lookups")
    args = parser.parse_args()

    slack_id = find_slack_id(args.user, args.channel, args.auth_token)
    if not slack_id:
        print("Slack ID not found, defaulting to username")
        slack_id = args.user

    url = args.jfrog_url
    if args.jfrog_url[-1] != "/":  # If the original link was a file, we go one level up to the parent directory
        url = args.jfrog_url.rsplit("/", 1)[0] + "/"
    url = url.replace("service/rest/repository/browse/", "repository/")
    url = convert_jfrog_url(url)
    text = ""
    if args.status=="SUCCESS":
        text += "Package Decryption: SUCCESS :green_circle:\n"
        text += f"Started by: {slack_id}\n"
        text += "The DSRU packages have been successfully decrypted\n"
        text += f"Package information can be found at: {url}\n"
        text += f"Full logs at: {args.build_url}console\n\n"
    else:
        text += "Package Decryption: FAILED :dot-red:\n"
        text += f"Started by: {slack_id}\n"
        if args.status == "STARTED":
            text += "Unable to download update packages from JFrog\n"
        elif args.status=="DECRYPT":
            text += "Failed to decrypt update packages\n"
        elif args.status=="PARSE":
            text += "Unable to parse update package information\n"
        elif args.status=="JFROG_UPLOAD":
            text += "Error while uploading to JFrog\n"
        text += f"Full logs at: {args.build_url}console\n\n"

    message = {"text": text}
    requests.post(args.webhook_url, data=json.dumps(message))

# Searches for the slack ID corresponding to the given username
def find_slack_id(slack_username, channel, auth_token):
    candidate_ids = []
    members = requests.get(f"https://slack.com/api/conversations.members?token={auth_token}&channel={channel}&limit=200").json()["members"]
    for member_id in members:
        member_info = requests.get(f"https://slack.com/api/users.info?token={auth_token}&user={member_id}").json()["user"]
        if ("real_name" in member_info and slack_username in member_info["real_name"]) or ("display_name" in member_info and slack_username in member_info["display_name"]):
            candidate_ids.append(f"<@{member_info['id']}>")
    if len(candidate_ids)==1:
        return candidate_ids[0]
    else:
        return ""

# Converts jfrog upload url into one that can be clicked on
def convert_jfrog_url(jfrog_url):
    cleaned_url = jfrog_url
    if "#" not in jfrog_url and "/repository/" in jfrog_url:
        host, loc = jfrog_url.split("/repository/")
        if loc.count("/") > 1:
            repo, folder, remainder = loc.split("/", 2)
        elif loc.count("/") == 1:
            repo, folder = loc.split("/")
            remainder = ""
        else:
            repo = loc
            folder = remainder = ""

        cleaned_url = f"{host}/#browse/browse:{repo}"
        if folder:
            cleaned_url += f":{folder}"
        if remainder:
            cleaned_url += f"%2F{remainder.strip('/').replace('/', '%2F')}"
    return cleaned_url

if __name__ == '__main__':
    main()
