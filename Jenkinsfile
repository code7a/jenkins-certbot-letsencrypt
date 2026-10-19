// Jenkinsfile: Let's Encrypt certificate issuance via certbot (DNS-01 / Route53), published to S3.
//
// Deliberately has NO `parameters {}` block. With "Pipeline script from SCM", Jenkins
// re-syncs a job's build-parameter definitions from the Jenkinsfile on every run — so
// any config you want to survive a `git pull` of this repo must live outside it, as
// environment variables set directly on the Jenkins job or (recommended) its Folder:
// Configure -> Properties -> Environment Variables. This file only ever reads them;
// it never defines or defaults them, so your Jenkins-side config is never overwritten.
// See README.md "Configuration" for the full variable list and setup steps.
//
// Every run forces a fresh issuance (--force-renewal) and overwrites fullchain.pem/privkey.pem
// at the root of the target S3 bucket — no renewal-state tracking is needed, so certbot's
// config/work/logs dirs just live under the workspace and are thrown away with it.
//
// Requires on the agent: python3 + venv module, bash. No root required — aws-cli and
// certbot are installed into a local virtualenv under the workspace.
//
// Requires in Jenkins: the AWS Credentials plugin (credential kind "AWS Credentials") and
// one such credential holding an IAM user's access key id + secret access key. That IAM
// user needs the policy in iam-policy.json attached — an access key alone grants no
// permissions; see README.md.

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        VENV_DIR    = "${WORKSPACE}/.venv"
        CERTBOT_DIR = "${WORKSPACE}/.certbot"
    }

    stages {

        // Reads this job's/Folder's CERTBOT_* environment variables, applies sane
        // fallback defaults for the non-identity ones, and fails fast if a required
        // identity variable (domain/zone/bucket) was never configured anywhere.
        stage('Resolve & Validate Configuration') {
            steps {
                script {
                    env.DOMAIN             = env.CERTBOT_DOMAIN?.trim()
                    env.HOSTED_ZONE_ID      = env.CERTBOT_HOSTED_ZONE_ID?.trim()
                    env.S3_BUCKET_NAME      = env.CERTBOT_S3_BUCKET?.trim()
                    env.INCLUDE_WILDCARD    = (env.CERTBOT_INCLUDE_WILDCARD?.trim() ?: 'false')
                    env.AWS_DEFAULT_REGION  = (env.CERTBOT_AWS_REGION?.trim() ?: 'us-east-1')
                    env.LETSENCRYPT_EMAIL   = (env.CERTBOT_EMAIL?.trim() ?: '')
                    env.ACME_SERVER         = (env.CERTBOT_ACME_SERVER?.trim() ?: 'production')
                    env.CERT_KEY_TYPE       = (env.CERTBOT_KEY_TYPE?.trim() ?: 'rsa')
                    env.AWS_CRED_ID = (env.CERTBOT_AWS_CRED_ID?.trim() ?: 'aws-certbot-access-key-id')

                    if (!env.DOMAIN) {
                        error "CERTBOT_DOMAIN is not set on this job/Folder. Configure -> Properties -> Environment Variables."
                    }
                    if (!env.HOSTED_ZONE_ID) {
                        error "CERTBOT_HOSTED_ZONE_ID is not set on this job/Folder."
                    }
                    if (!env.S3_BUCKET_NAME) {
                        error "CERTBOT_S3_BUCKET is not set on this job/Folder."
                    }
                    if (!(env.ACME_SERVER in ['production', 'staging'])) {
                        error "CERTBOT_ACME_SERVER must be 'production' or 'staging', got '${env.ACME_SERVER}'."
                    }
                    if (!(env.CERT_KEY_TYPE in ['rsa', 'ecdsa'])) {
                        error "CERTBOT_KEY_TYPE must be 'rsa' or 'ecdsa', got '${env.CERT_KEY_TYPE}'."
                    }

                    echo "Domain:       ${env.DOMAIN}${env.INCLUDE_WILDCARD == 'true' ? ' (+ *.' + env.DOMAIN + ')' : ''}"
                    echo "Key type:     ${env.CERT_KEY_TYPE}"
                    echo "ACME server:  ${env.ACME_SERVER}"
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: env.AWS_CRED_ID,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: env.AWS_CRED_ID,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: env.AWS_CRED_ID,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: env.AWS_CRED_ID,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
                        if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
                            EMAIL_ARGS="--email ${LETSENCRYPT_EMAIL:-}"
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
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: env.AWS_CRED_ID,
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
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
