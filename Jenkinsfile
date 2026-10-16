// Jenkinsfile: Let's Encrypt certificate issuance via certbot (DNS-01 / Route53), published to S3.
//
// Every run forces a fresh issuance (--force-renewal) and overwrites fullchain.pem/privkey.pem
// at the root of the target S3 bucket — no renewal-state tracking is needed, so certbot's
// config/work/logs dirs just live under the workspace and are thrown away with it.
//
// Requires on the agent: python3 + venv module, bash. No root required — aws-cli and
// certbot are installed into a local virtualenv under the workspace.
//
// Requires in Jenkins: Credentials Binding plugin (core, almost always present) and two
// "Secret text" credentials holding an IAM user's access key id / secret access key. That
// IAM user needs the policy in iam-policy.json attached — an access key alone grants no
// permissions; see README.md.

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    parameters {
        choice(
            name: 'DOMAIN_NAME',
            choices: ['CUSTOM', 'example.com', 'www.example.com'],
            description: 'Domain to request a certificate for. Leave on CUSTOM with CUSTOM_DOMAIN_NAME blank to use this job/folder\'s persistent CERTBOT_DEFAULT_DOMAIN env var (see README) — that is what unattended/cron-triggered builds will use.'
        )
        string(
            name: 'CUSTOM_DOMAIN_NAME',
            defaultValue: '',
            description: 'Only used when DOMAIN_NAME = CUSTOM. Leave blank to fall back to the CERTBOT_DEFAULT_DOMAIN env var; fill in to override for one build.'
        )
        booleanParam(
            name: 'INCLUDE_WILDCARD',
            defaultValue: false,
            description: 'Also request *.<domain> as a SAN alongside the base domain'
        )
        string(
            name: 'HOSTED_ZONE_ID',
            defaultValue: '',
            description: 'Route53 hosted zone ID that contains the domain. Leave blank to fall back to the CERTBOT_DEFAULT_HOSTED_ZONE_ID env var; fill in to override for one build.'
        )
        string(
            name: 'S3_BUCKET_NAME',
            defaultValue: '',
            description: 'S3 bucket fullchain.pem/privkey.pem are uploaded to (bucket root, overwritten every build). Leave blank to fall back to the CERTBOT_DEFAULT_S3_BUCKET env var; fill in to override for one build.'
        )
        string(
            name: 'AWS_REGION',
            defaultValue: 'us-east-1',
            description: 'Region for S3/STS API calls (Route53 itself is global)'
        )
        string(
            name: 'LETSENCRYPT_EMAIL',
            defaultValue: '',
            description: "Optional contact email for Let's Encrypt expiry/account notices. Leave blank to fall back to the CERTBOT_DEFAULT_EMAIL env var if set, otherwise registers without one (--register-unsafely-without-email)."
        )
        choice(
            name: 'ACME_SERVER',
            choices: ['production', 'staging'],
            description: "Which ACME endpoint certbot talks to. Defaults to production; switch to 'staging' when testing changes to this pipeline to avoid Let's Encrypt production rate limits (5 duplicate certs/week per domain set)"
        )
        choice(
            name: 'CERT_KEY_TYPE',
            choices: ['rsa', 'ecdsa'],
            description: 'Private key algorithm for the issued certificate: rsa (2048-bit) or ecdsa (secp384r1)'
        )
        string(
            name: 'AWS_ACCESS_KEY_CRED_ID',
            defaultValue: 'aws-certbot-access-key-id',
            description: 'Jenkins "Secret text" credential ID holding the AWS access key ID'
        )
        string(
            name: 'AWS_SECRET_KEY_CRED_ID',
            defaultValue: 'aws-certbot-secret-access-key',
            description: 'Jenkins "Secret text" credential ID holding the AWS secret access key'
        )
    }

    environment {
        VENV_DIR           = "${WORKSPACE}/.venv"
        CERTBOT_DIR        = "${WORKSPACE}/.certbot"
        AWS_DEFAULT_REGION = "${params.AWS_REGION}"
    }

    stages {

        // Resolves each identity/location value as: explicit build parameter, else a
        // CERTBOT_DEFAULT_* environment variable set at the Jenkins Folder or global level
        // (outside this repo, so it survives Jenkinsfile updates and is what unattended/
        // cron-triggered builds fall back to). See README "Persistent per-job config".
        stage('Validate Parameters') {
            steps {
                script {
                    env.DOMAIN = (params.DOMAIN_NAME == 'CUSTOM' ? params.CUSTOM_DOMAIN_NAME : params.DOMAIN_NAME)?.trim()
                    if (!env.DOMAIN) { env.DOMAIN = env.CERTBOT_DEFAULT_DOMAIN?.trim() }

                    env.HOSTED_ZONE_ID = params.HOSTED_ZONE_ID?.trim() ?: env.CERTBOT_DEFAULT_HOSTED_ZONE_ID?.trim()
                    env.S3_BUCKET_NAME = params.S3_BUCKET_NAME?.trim() ?: env.CERTBOT_DEFAULT_S3_BUCKET?.trim()
                    env.LETSENCRYPT_EMAIL = params.LETSENCRYPT_EMAIL?.trim() ?: (env.CERTBOT_DEFAULT_EMAIL?.trim() ?: '')

                    if (!env.DOMAIN) {
                        error "No domain supplied: CUSTOM_DOMAIN_NAME was blank and no CERTBOT_DEFAULT_DOMAIN env var is set on this job/folder."
                    }
                    if (!env.HOSTED_ZONE_ID) {
                        error "No HOSTED_ZONE_ID supplied and no CERTBOT_DEFAULT_HOSTED_ZONE_ID env var is set on this job/folder."
                    }
                    if (!env.S3_BUCKET_NAME) {
                        error "No S3_BUCKET_NAME supplied and no CERTBOT_DEFAULT_S3_BUCKET env var is set on this job/folder."
                    }

                    echo "Domain:       ${env.DOMAIN}${params.INCLUDE_WILDCARD ? ' (+ *.' + env.DOMAIN + ')' : ''}"
                    echo "Key type:     ${params.CERT_KEY_TYPE}"
                    echo "ACME server:  ${params.ACME_SERVER}"
                    echo "Hosted zone:  ${env.HOSTED_ZONE_ID}"
                    echo "S3 target:    s3://${env.S3_BUCKET_NAME}/{fullchain,privkey}.pem"
                }
            }
        }

        stage('Set Up Tooling (aws-cli + certbot)') {
            steps {
                sh '''
                    set -euo pipefail
                    command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 is required on this agent"; exit 1; }

                    if [ ! -x "${VENV_DIR}/bin/aws" ] || [ ! -x "${VENV_DIR}/bin/certbot" ]; then
                        echo "Installing aws-cli + certbot + certbot-dns-route53 into ${VENV_DIR} ..."
                        python3 -m venv "${VENV_DIR}"
                        "${VENV_DIR}/bin/pip" install --upgrade pip --quiet
                        "${VENV_DIR}/bin/pip" install --quiet awscli certbot certbot-dns-route53
                    else
                        echo "aws-cli / certbot already installed, skipping."
                    fi

                    . "${VENV_DIR}/bin/activate"
                    echo "--- versions ---"
                    aws --version
                    certbot --version
                    certbot plugins --text | grep -qi route53 || { echo "ERROR: certbot-dns-route53 plugin not found"; exit 1; }
                '''
            }
        }

        stage('Validate AWS Access') {
            steps {
                withCredentials([
                    string(credentialsId: params.AWS_ACCESS_KEY_CRED_ID, variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: params.AWS_SECRET_KEY_CRED_ID, variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh '''
                        set -euo pipefail
                        . "${VENV_DIR}/bin/activate"
                        echo "Checking AWS credentials are valid..."
                        aws sts get-caller-identity
                    '''
                }
            }
        }

        stage('Validate Route53 Permissions') {
            steps {
                withCredentials([
                    string(credentialsId: params.AWS_ACCESS_KEY_CRED_ID, variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: params.AWS_SECRET_KEY_CRED_ID, variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh '''
                        set -euo pipefail
                        . "${VENV_DIR}/bin/activate"

                        echo "Checking route53:ListHostedZones ..."
                        aws route53 list-hosted-zones --max-items 1 >/dev/null

                        echo "Checking route53:ListHostedZonesByName for ${DOMAIN} ..."
                        aws route53 list-hosted-zones-by-name --dns-name "${DOMAIN}" >/dev/null

                        echo "Checking route53:GetHostedZone for ${HOSTED_ZONE_ID} ..."
                        ZONE_NAME=$(aws route53 get-hosted-zone --id "${HOSTED_ZONE_ID}" --query 'HostedZone.Name' --output text)
                        ZONE_NAME="${ZONE_NAME%.}"

                        case ".${DOMAIN}." in
                            *".${ZONE_NAME}."*) echo "OK: ${DOMAIN} is within zone ${ZONE_NAME}" ;;
                            *) echo "ERROR: ${DOMAIN} does not belong to hosted zone ${ZONE_NAME} (${HOSTED_ZONE_ID})"; exit 1 ;;
                        esac
                    '''
                }
            }
        }

        stage('Validate S3 Permissions') {
            steps {
                withCredentials([
                    string(credentialsId: params.AWS_ACCESS_KEY_CRED_ID, variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: params.AWS_SECRET_KEY_CRED_ID, variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh '''
                        set -euo pipefail
                        . "${VENV_DIR}/bin/activate"

                        MARKER_KEY="_healthcheck/${BUILD_NUMBER}.txt"
                        echo "Checking s3:PutObject on s3://${S3_BUCKET_NAME}/${MARKER_KEY} ..."
                        echo "jenkins-certbot healthcheck $(date -u +%FT%TZ)" > /tmp/healthcheck.txt
                        aws s3 cp /tmp/healthcheck.txt "s3://${S3_BUCKET_NAME}/${MARKER_KEY}"

                        echo "Checking s3:GetObject ..."
                        aws s3 cp "s3://${S3_BUCKET_NAME}/${MARKER_KEY}" /tmp/healthcheck-read.txt >/dev/null
                        rm -f /tmp/healthcheck.txt /tmp/healthcheck-read.txt

                        echo "OK: S3 put/get verified. (Note: this IAM policy intentionally has no DeleteObject permission — add a lifecycle rule on the _healthcheck/ prefix to auto-expire these marker objects. See README.)"
                    '''
                }
            }
        }

        stage('Request Certificate (certbot + Route53 DNS-01)') {
            steps {
                withCredentials([
                    string(credentialsId: params.AWS_ACCESS_KEY_CRED_ID, variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: params.AWS_SECRET_KEY_CRED_ID, variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh '''
                        set -euo pipefail
                        . "${VENV_DIR}/bin/activate"
                        mkdir -p "${CERTBOT_DIR}/config" "${CERTBOT_DIR}/work" "${CERTBOT_DIR}/logs"

                        DOMAIN_ARGS="-d ${DOMAIN}"
                        if [ "${INCLUDE_WILDCARD}" = "true" ]; then
                            DOMAIN_ARGS="${DOMAIN_ARGS} -d *.${DOMAIN}"
                        fi

                        SERVER_ARG=""
                        if [ "${ACME_SERVER}" = "staging" ]; then
                            SERVER_ARG="--staging"
                        fi

                        if [ "${CERT_KEY_TYPE}" = "ecdsa" ]; then
                            KEY_TYPE_ARGS="--key-type ecdsa --elliptic-curve secp384r1"
                        else
                            KEY_TYPE_ARGS="--key-type rsa --rsa-key-size 2048"
                        fi

                        EMAIL_ARGS="--register-unsafely-without-email"
                        if [ -n "${LETSENCRYPT_EMAIL}" ]; then
                            EMAIL_ARGS="--email ${LETSENCRYPT_EMAIL}"
                        fi

                        # certbot-dns-route53 auto-discovers the matching hosted zone (ListHostedZonesByName),
                        # creates the _acme-challenge TXT record (ChangeResourceRecordSets UPSERT), polls
                        # until it's INSYNC (GetChange), lets the CA validate it, then deletes the TXT
                        # record (ChangeResourceRecordSets DELETE) once validation completes.
                        certbot certonly \
                            --non-interactive \
                            --agree-tos \
                            --force-renewal \
                            ${EMAIL_ARGS} \
                            --dns-route53 \
                            --dns-route53-propagation-seconds 30 \
                            --config-dir "${CERTBOT_DIR}/config" \
                            --work-dir "${CERTBOT_DIR}/work" \
                            --logs-dir "${CERTBOT_DIR}/logs" \
                            ${SERVER_ARG} \
                            ${KEY_TYPE_ARGS} \
                            ${DOMAIN_ARGS}
                    '''
                }
            }
        }

        stage('Upload Certificate to S3') {
            steps {
                withCredentials([
                    string(credentialsId: params.AWS_ACCESS_KEY_CRED_ID, variable: 'AWS_ACCESS_KEY_ID'),
                    string(credentialsId: params.AWS_SECRET_KEY_CRED_ID, variable: 'AWS_SECRET_ACCESS_KEY')
                ]) {
                    sh '''
                        set -euo pipefail
                        . "${VENV_DIR}/bin/activate"

                        LIVE_DIR="${CERTBOT_DIR}/config/live/${DOMAIN}"
                        if [ ! -d "${LIVE_DIR}" ]; then
                            echo "ERROR: expected certbot output at ${LIVE_DIR}, not found"
                            exit 1
                        fi
                        chmod 600 "${LIVE_DIR}/privkey.pem"

                        for f in fullchain.pem privkey.pem; do
                            echo "Uploading ${f} ..."
                            aws s3 cp "${LIVE_DIR}/${f}" "s3://${S3_BUCKET_NAME}/${f}" --sse AES256
                        done
                    '''
                }
            }
        }
    }

    post {
        always {
            // Only the certbot logs are archived — never the live/ directory, so private keys
            // never land in Jenkins' build artifact storage (which is visible to any job reader).
            archiveArtifacts artifacts: '.certbot/**/logs/*.log', allowEmptyArchive: true, fingerprint: false
        }
        success {
            echo "Certificate for ${env.DOMAIN} issued and uploaded to s3://${env.S3_BUCKET_NAME}/{fullchain,privkey}.pem"
        }
        failure {
            echo "Pipeline failed — check the certbot log artifact and the failing AWS CLI call in the stage logs above."
        }
    }
}
