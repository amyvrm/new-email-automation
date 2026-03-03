# Downloads update packages (DSRU, VP, IDF, iVP IDF_SERVERS) from Nexus
# Works on both individual files and folders

import requests
import zipfile
import re
import argparse
import os

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", type=str, help="Package Version")
    parser.add_argument("--jfrog_token", type=str, help="JFrog token")
    args = parser.parse_args()
    with requests.Session() as s:

        url = args.url.strip()

        # We first have to decide whether the url is a folder or a specific file
        packages = []
        packages_version = []
        if url[-1] == "/":  # We have been passed a link to a folder
            print("URL appears to be folder, collecting list of potential update packages")
            r = s.get(url, headers={'Authorization': 'Bearer '+args.jfrog_token})
            packages = map(lambda x : f"{url}{x}", [link for link in re.findall(r'<a href=\"(.*)?\">', r.text) if link != "../"])
            print("Found:")
            for package in packages:
                print(f"\t{package}")
        else:  # We have been passed a link directly to an update package
            # packages = url.split(",")
            packages_version = url.split(",")

        # Then, once we have a list of potential package links, collect them all
        print("\nCollecting update packages")
        if not os.path.exists("update-packages"):
            os.makedirs("update-packages")
        #packages = []
        base_url = "https://jfrog.trendmicro.com/artifactory/dslabs-issued-dsru-generic-archive-local"
     #   base_url = "https://jfrog.trendmicro.com/artifactory/dslabs-sample-dsru-generic-archive-local"
    
        for pkg_ver in packages_version:
            pkg_ver = pkg_ver.replace("-", "")
            # DSRUSecurityUpdate/2002300/dsru20023.zip
            dsru_url = "{}/DSRUSecurityUpdate/{}00/dsru{}.zip".format(base_url, pkg_ver, pkg_ver)
            packages.append(dsru_url)
            """
            Phasing out IDF/VP Package.
            # IDFSecurityUpdate/20023/IdfSecurityUpdate20023.zip
            idf_url = "{}/IDFSecurityUpdate/{}/IdfSecurityUpdate{}.zip".format(base_url, pkg_ver, pkg_ver)
            packages.append(idf_url)
            # VPSecurityUpdate/20023/VPSecurityUpdate20023.zip
            vp_url = "{}/VPSecurityUpdate/{}/VPSecurityUpdate{}.zip".format(base_url, pkg_ver, pkg_ver)
            packages.append(vp_url)
            """
            # iVPSecurityUpdate/20023/iVPSecurityUpdate20023.zip
            ivp_url = "{}/iVPSecurityUpdate/{}/iVPSecurityUpdate{}.zip".format(base_url, pkg_ver, pkg_ver)
            packages.append(ivp_url)

        for package in packages:
            name, ext = os.path.splitext(package.rsplit("/",1)[-1])
            if ext != ".zip" and ext != ".3bsu" and ext != ".dsru":  # Update should be one of these three filetypes
                print(f"\tSkipping {name}{ext}")
                continue

            print(f"\tDownloading {name}{ext}")
            r = s.get(package, headers={'Authorization': 'Bearer '+args.jfrog_token})
            package_path = os.path.join("update-packages", f"{name}{ext}")
            with open(package_path, "wb") as f:
                f.write(r.content)
            if ext == ".zip":  # We are only interested in the internals of the zip file, so can just unzip
                with zipfile.ZipFile(package_path, 'r') as fz:
                    fz.extractall("update-packages")
                os.remove(package_path)

if __name__ == '__main__':
    main()
