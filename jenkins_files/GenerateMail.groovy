#!/usr/bin/env groovy

def prev_dsru = "None"
def user_name = "None"
def email_id = "None"
def msg = "None"
def email_msg = "None"

pipeline {
    agent {
        dockerfile {
            label 'aws&&docker'
            // docker file path
            dir 'docker_files'
            filename 'DockerfileMail'
        }
    }
    // parameters are listed below
    parameters {
        string defaultValue: '', description: 'Example: 19-062', name: 'DSRU_Version', trim: false
        string defaultValue: '', description: 'Example: YYYY-MM-DD', name: 'Issue_Date', trim: false
        booleanParam defaultValue: false, description: 'Tick - Tick box for DSRU Highlights', name: 'DSRU_Highlights'
        text defaultValue: 'Please write highlights manually',
              description: 'Above lines will be added in DSRU Highlights email body', name: 'DSRU_Highlights_Contains'
        /*
        Phasing out IDF/VP Package.
        booleanParam defaultValue: false, description: 'Tick - Tick box for TMVP Highlights', name: 'TMVP_Highlights'
        text defaultValue: 'Please write highlights manually',
              description: 'Above lines will be added in TMVP Highlights email body', name: 'TMVP_Highlights_Contains'
        */
        booleanParam defaultValue: false, description: 'Tick - Tick box for IVP Highlights', name: 'IVP_Highlights'
        text defaultValue: 'Please write highlights manually',
              description: 'Above lines will be added in IVP Highlights email body', name: 'IVP_Highlights_Contains'

        booleanParam defaultValue: false, description: 'Tick - Tick box for Microsoft Table', name: 'MS_Table'
        booleanParam defaultValue: false, description: 'Tick - Tick box for Adobe Table', name: 'Adobe_Table'
        string defaultValue: 'false', description: 'Example: APSB**-**', name: 'Bulletin_id', trim: false
    }

    // credentials
    environment {
        JFROG_URL = "https://jfrog.trendmicro.com/artifactory/dslabs-dsru-generic-test-local/"
        JIRA_CRED = credentials('su-dslabs-creds')
        JFROG_TOKEN = credentials('dsdeploy-artifactory-token')
        //JIRA_CRED = credentials('test_jira_user')
        WEBHOOK = credentials('jenkins-webhook')
        SLACK_WEBHOOK = credentials('dsru-auto-dsruhandover-webhook')
        EMAIL_INFORM = 'amit_verma@trendmicro.com'
    }

    stages {
        // format previous version based on supplied version dsru version
        stage('Calculate Previous Version') {
            steps {
                script {
                    wrap([$class: 'BuildUser'])
                    {
                        user_name = "${env.BUILD_USER}"
                        email_id = "${env.BUILD_USER_EMAIL}"
                    }
                    slackSend channel: 'dslabs_auto_monitoring', color: "good",
                        message: "Job triggered ${env.JOB_BASE_NAME} build ${env.BUILD_NUMBER}: started by ${user_name}"
                    def splited_ver = params.DSRU_Version.split("-")
                    echo "DSRU Version: ${splited_ver[1]}"
                    if ("${splited_ver[1]}" != "001") {
                        def temp = "${splited_ver[1]}".toInteger() - 1
                        echo "Auto Previous version: ${temp}"
                        len = "${temp}".length()
                        echo "length: ${len}"
                        if (len == 2) {
                            prev_dsru = "${splited_ver[0]}-0${temp}"
                            echo "prev_dsru: ${prev_dsru}"
                        }
                        if (len == 1 && temp > 1) {
                            echo "temp > 1 -> ${temp} > 1"
                            prev_dsru = "${splited_ver[0]}-00${temp}"
                            echo "prev_dsru: ${prev_dsru}"
                        }
                    }
                    echo "Previous DSRU Version: ${prev_dsru}"
                }
            }
        }
        // If unable to get the previous version
        stage('Get Previous Version') {
            when {
                beforeInput true
                expression { prev_dsru == "None" }
            }
            input {
                message 'Please provide previous DSRU version'
                ok 'Submit, It helps in rule update reason'
                parameters {
                    string defaultValue: '', description: 'Example: 19-062', name: 'Prev_DSRU_Ver', trim: false
                }
            }
            steps {
                script {
                    prev_dsru = Prev_DSRU_Ver
                    echo "Previous DSRU Version: ${prev_dsru}"
                }
            }
        }
        // fetching the supplied version dsru json file and previous version dsru json file to calculate difference
        // this json file will processed in the code
        stage('Decrpt and Upload') {
            steps {
                script {
                    def package_url = "None"
                    // dsru-decrypted-files/20-023/20-023.json
                    dsru_url = "${JFROG_URL}${params.DSRU_Version}/${params.DSRU_Version}.json"
                    dsru_url_prev = "${JFROG_URL}${prev_dsru}/${prev_dsru}.json"

                    //int status_code = sh(script: "curl -sLI -w '%{http_code}' $dsru_url -o /dev/null", returnStdout: true)
                    //$JIRA_CRED_USR --password $JIRA_CRED_PSW
                    String status_code = sh(script: "curl -H 'Authorization: Bearer $JFROG_TOKEN' -sLI -w '%{http_code}' $dsru_url -o /dev/null", returnStdout: true)
                    //int status_code_prev = sh(script: "curl -sLI -w '%{http_code}' $dsru_url_prev -o /dev/null", returnStdout: true)
                    String status_code_prev = sh(script: "curl -H'Authorization: Bearer $JFROG_TOKEN' -sLI -w '%{http_code}' $dsru_url_prev -o /dev/null", returnStdout: true)
                    echo "- Http Status Code of DSRU Version: ${status_code}"
                    echo "- Http Status Code of Previous DSRU Version: ${status_code_prev}"

                    status_code = status_code.toString()
                    if( status_code == "404" && status_code_prev == "404" )
                    {
                        echo "### Both decrpted DSRU json files are not present ###"
                        package_url = "${params.DSRU_Version},${prev_dsru}"
                        echo "Package version will for decryption: ${package_url}"
                    }
                    else if (status_code == "404")
                    {
                        echo "### Current decrpted DSRU json file is not present ###"
                        package_url = "${params.DSRU_Version}"
                        echo "Package version will for decryption: ${package_url}"
                    }
                    else if (status_code_prev == "404")
                    {
                        echo "### Previous Decrpted DSRU json file is not present ###"
                        package_url = "${prev_dsru}"
                        echo "Package version will for decryption: ${package_url}"
                    }

                    if (package_url != "None")
                    {
                        build quietPeriod: 10, job: 'dsru_release/decrypt_dsru_package',
                              parameters: [string(name: 'package_url', value: "${package_url}")]
                    }
                }
            }
        }
        // code to process and the information and draft mail in html
        stage('Process Mail Content') {
            steps {
                script {
                    echo "bulletin_id $params.Bulletin_id"
                    /*
                    Phasing out IDF/VP Package.
                    sh ("python3 src/generate_all_mails.py --dsru_ver $params.DSRU_Version \
                            --prev_dsru_ver $prev_dsru \
                            --issue_Date $params.Issue_Date \
                            --dsru_flag $params.DSRU_Highlights \
                            --dsru_high \"$params.DSRU_Highlights_Contains\" \
                            --idf_flag $params.TMVP_Highlights \
                            --idf_high \"$params.TMVP_Highlights_Contains\" \
                            --ivp_flag $params.IVP_Highlights \
                            --ivp_high \"$params.IVP_Highlights_Contains\" \
                            --ms_flag $params.MS_Table \
                            --adobe_flag $params.Adobe_Table \
                            --jira_uname ${JIRA_CRED_USR} --jira_pwd ${JIRA_CRED_PSW} \
                            --url $JFROG_URL \
                            --bulletin_id $params.Bulletin_id \
                            --jfrog_token ${JFROG_TOKEN} \
                            --webhook ${WEBHOOK} \
                            --jenkins_build ${env.BUILD_URL} \
                            --slack_webhook ${SLACK_WEBHOOK}")
                    */
                    sh ("python3 src/generate_all_mails.py --dsru_ver $params.DSRU_Version \
                            --prev_dsru_ver $prev_dsru \
                            --issue_Date $params.Issue_Date \
                            --dsru_flag $params.DSRU_Highlights \
                            --dsru_high \"$params.DSRU_Highlights_Contains\" \
                            --ivp_flag $params.IVP_Highlights \
                            --ivp_high \"$params.IVP_Highlights_Contains\" \
                            --ms_flag $params.MS_Table \
                            --adobe_flag $params.Adobe_Table \
                            --jira_uname ${JIRA_CRED_USR} --jira_pwd ${JIRA_CRED_PSW} \
                            --url $JFROG_URL \
                            --bulletin_id $params.Bulletin_id \
                            --jfrog_token ${JFROG_TOKEN} \
                            --webhook ${WEBHOOK} \
                            --jenkins_build ${env.BUILD_URL} \
                            --slack_webhook ${SLACK_WEBHOOK}")
                }
            }
        }
        // send all email to users email id
        stage('Send Mail') {
            steps {
                script {
                    email_msg = readFile "dsru_mail.html"
                    mail ( mimeType: "text/html",
                            subject: "Cloud One Workload Security/Deep Security Update: DSRU ${params.DSRU_Version} Issued",
                            body: "${email_msg}",
                            to: "${email_id}")
                    /*
                    Phasing out IDF/VP Package.
                    email_msg = readFile "tmvp_mail.html"
                    mail ( mimeType: "text/html",
                            subject: "Trend Micro Vulnerability Protection: TMVP ${params.DSRU_Version} Issued",
                            body: "${email_msg}",
                            to: "${email_id}")
                    email_msg = readFile "vp_mail.html"
                    mail ( mimeType: "text/html",
                                subject: "Trend Micro Vulnerability Protection ${params.DSRU_Version}",
                                body: "${email_msg}",
                                to: "${email_id}")
                    */
                    email_msg = readFile "ivp_mail.html"
                    mail ( mimeType: "text/html",
                                subject: "Trend Micro Apex One Integrated Vulnerability Protection (iVP): TMiVP ${params.DSRU_Version} Issued",
                                body: "${email_msg}",
                                to: "${email_id}")
                    email_msg = readFile "psp_dsru_mail.html"
                    mail ( mimeType: "text/html",
                                subject: "Cloud One Workload Security/Deep Security Update ${params.DSRU_Version}",
                                body: "${email_msg}",
                                to: "${email_id}")
                }
                archiveArtifacts artifacts: 'dsru_mail.html,tmvp_mail.html,ivp_mail.html,vp_mail.html,psp_dsru_mail.html',
                                 onlyIfSuccessful: true
            }
        }
        // update the current dsru version
        stage('Update Release File') {
            steps {
                script {
                    release_file = "release.txt"
                    content = "${params.DSRU_Version}:${params.Issue_Date}"
                    sh "echo ${content} > ${release_file}"
                    sh "ls -1"
                    // Delete Existing Eile
                    sh "curl -H'Authorization: Bearer $JFROG_TOKEN' -X DELETE ${JFROG_URL}${release_file} --fail -v"
                    // Create New File
                    sh "curl -H'Authorization: Bearer $JFROG_TOKEN' --upload-file ${release_file} ${JFROG_URL}${release_file} --fail -v"
                }
            }
        }
    }
    post {
        always {
            script {
                msg = "${currentBuild.currentResult}: Job ${env.JOB_BASE_NAME} build "
                msg += "${env.BUILD_NUMBER} started by ${user_name}\nMore info: ${env.BUILD_URL}"
                cleanWs()
            }
        }
        success {
            slackSend channel: 'dslabs_auto_monitoring', color: "good",
                      message: "New Automation Email V2 has been Executed Successfully\n${msg}"
        }
        failure {
            slackSend channel: 'dslabs_auto_monitoring', color: "danger", message: "${msg}"
            mail body: "${msg}", subject: "${currentBuild.currentResult}: ${env.JOB_BASE_NAME} Pipeline",
                 to: "${EMAIL_INFORM}"
        }
    }
}
