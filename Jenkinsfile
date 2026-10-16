// Jenkinsfile: Let's Encrypt certificate issuance via certbot (DNS-01 / Route53), published to S3.
//
// Requires on the agent: python3 + venv module, bash. No root required — aws-cli and
// certbot are installed into a local virtualenv under the workspace (or CERTBOT_BASE_DIR).
//
// Requires in Jenkins: Credentials Binding plugin (core, almost always present) and two
// "Secret text" credentials holding an IAM user's access key id / secret access key.
// See README.md for the IAM policy and credential setup.

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
            choices: ['example.com', 'www.example.com', 'CUSTOM'],
            description: 'Domain to request a certificate for. Edit this list to your real domains. Pick CUSTOM to type an arbitrary one below.'
        )
        string(
            name: 'CUSTOM_DOMAIN_NAME',
            defaultValue: '',
            description: 'Only used when DOMAIN_NAME = CUSTOM, e.g. api.example.com'
        )
        booleanParam(
            name: 'INCLUDE_WILDCARD',
            defaultValue: false,
            description: 'Also request *.<domain> as a SAN alongside the base domain'
        )
        string(
            name: 'HOSTED_ZONE_ID',
            defaultValue: 'Z0123456789ABCDEFGHIJ',
            description: 'Route53 hosted zone ID that contains DOMAIN_NAME (used to validate permissions/ownership before certbot runs)'
        )
        string(
            name: 'S3_BUCKET_NAME',
            defaultValue: 'my-certbot-cert-bucket',
            description: 'S3 bucket the issued certificate files are uploaded to'
        )
        string(
            name: 'S3_PREFIX',
            defaultValue: 'certificates',
            description: 'Key prefix inside the bucket; certs land at <prefix>/<domain>/'
        )
        string(
            name: 'AWS_REGION',
            defaultValue: 'us-east-1',
            description: 'Region for S3/STS API calls (Route53 itself is global)'
        )
        string(
            name: 'LETSENCRYPT_EMAIL',
            defaultValue: 'ops@example.com',
            description: "Registration/expiry-notice email passed to certbot"
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
        string(
            name: 'CERTBOT_BASE_DIR',
            defaultValue: '',
            description: 'Optional: absolute path on the agent to persist certbot state (account registration, renewal history) across builds, e.g. /var/lib/jenkins-certbot. Leave blank to use the workspace (state will NOT survive workspace wipes).'
        )
    }

    environment {
        VENV_DIR           = "${WORKSPACE}/.venv"
        CERTBOT_DIR        = "${params.CERTBOT_BASE_DIR.trim() ? params.CERTBOT_BASE_DIR + '/' + env.JOB_NAME : WORKSPACE + '/.certbot'}"
        DOMAIN             = "${params.DOMAIN_NAME == 'CUSTOM' ? params.CUSTOM_DOMAIN_NAME.trim() : params.DOMAIN_NAME}"
        AWS_DEFAULT_REGION = "${params.AWS_REGION}"
    }

    stages {

        stage('Validate Parameters') {
            steps {
                script {
                    if (!env.DOMAIN?.trim()) {
                        error "DOMAIN_NAME is CUSTOM but CUSTOM_DOMAIN_NAME was left blank."
                    }
                    if (!params.HOSTED_ZONE_ID?.trim() || !params.S3_BUCKET_NAME?.trim()) {
                        error "HOSTED_ZONE_ID and S3_BUCKET_NAME are required."
                    }
                    echo "Domain:       ${env.DOMAIN}${params.INCLUDE_WILDCARD ? ' (+ *.' + env.DOMAIN + ')' : ''}"
                    echo "Key type:     ${params.CERT_KEY_TYPE}"
                    echo "ACME server:  ${params.ACME_SERVER}"
                    echo "Hosted zone:  ${params.HOSTED_ZONE_ID}"
                    echo "S3 target:    s3://${params.S3_BUCKET_NAME}/${params.S3_PREFIX}/${env.DOMAIN}/"
                    echo "Certbot dir:  ${env.CERTBOT_DIR}"
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

                        MARKER_KEY="${S3_PREFIX}/_healthcheck/${BUILD_NUMBER}.txt"
                        echo "Checking s3:PutObject on s3://${S3_BUCKET_NAME}/${MARKER_KEY} ..."
                        echo "jenkins-certbot healthcheck $(date -u +%FT%TZ)" > /tmp/healthcheck.txt
                        aws s3 cp /tmp/healthcheck.txt "s3://${S3_BUCKET_NAME}/${MARKER_KEY}"

                        echo "Checking s3:GetObject ..."
                        aws s3 cp "s3://${S3_BUCKET_NAME}/${MARKER_KEY}" /tmp/healthcheck-read.txt >/dev/null
                        rm -f /tmp/healthcheck.txt /tmp/healthcheck-read.txt

                        echo "OK: S3 put/get verified. (Note: this IAM policy intentionally has no DeleteObject permission — add a lifecycle rule on the ${S3_PREFIX}/_healthcheck/ prefix to auto-expire these marker objects. See README.)"
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

                        # certbot-dns-route53 auto-discovers the matching hosted zone (ListHostedZonesByName),
                        # creates the _acme-challenge TXT record (ChangeResourceRecordSets UPSERT), polls
                        # until it's INSYNC (GetChange), lets the CA validate it, then deletes the TXT
                        # record (ChangeResourceRecordSets DELETE) once validation completes.
                        certbot certonly \
                            --non-interactive \
                            --agree-tos \
                            --email "${LETSENCRYPT_EMAIL}" \
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

                        for f in fullchain.pem privkey.pem cert.pem chain.pem; do
                            echo "Uploading ${f} ..."
                            aws s3 cp "${LIVE_DIR}/${f}" "s3://${S3_BUCKET_NAME}/${S3_PREFIX}/${DOMAIN}/${f}" --sse AES256
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
            echo "Certificate for ${env.DOMAIN} issued and uploaded to s3://${params.S3_BUCKET_NAME}/${params.S3_PREFIX}/${env.DOMAIN}/"
        }
        failure {
            echo "Pipeline failed — check the certbot log artifact and the failing AWS CLI call in the stage logs above."
        }
    }
}
