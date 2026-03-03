# Uploads the update package info to Nexus

import argparse
import requests
import os
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", type=str, help="Uplaod Url")
    parser.add_argument("--jfrog_token", type=str, help="JFrog Credentials")
    args = parser.parse_args()

    url = args.url.strip()
    print("# url: {} ".format(url))
    if url[-1] != "/":  # If the original link was a file, we go one level up to the parent directory
        url = url.rsplit("/", 1)[0] + "/"

    # Upload API isn't the same as the browsing API
    # Only applies when passing in a folder
    url = url.replace("service/rest/repository/browse/", "repository/")

    with requests.Session() as s:
        s.headers = {'Authorization': 'Bearer '+args.jfrog_token}

        for filename in os.listdir("update-packages"):
            if os.path.splitext(filename)[-1] == ".json":
                with open(os.path.join("update-packages", filename), "rb") as f:
                    data = f.read()
                    s.delete(f"{url}/{filename}")
                    r = s.put(f"{url}/{filename}", data=data)
                    if r.status_code != 201:
                        print(f"Upload failed: {r}")
                        sys.exit(-1)

if __name__ == '__main__':
    main()
