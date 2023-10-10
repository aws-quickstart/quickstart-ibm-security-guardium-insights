#!/bin/bash

SCRIPT=${0##*/}
echo $SCRIPT
source /etc/profile.d/gi_install.sh
source ${P}

# Function to signal the wait condition handle (GIInstallationCompletedURL) status from cfn-init
cfn_init_status() {
    /usr/bin/cfn-signal -s false -r "FAILURE: Bootstrap action failed. Error executing bootstrap script. ${failure_msg}" $GIInstallationCompletedURL
    sleep 300
    aws ssm put-parameter --name $AWS_STACKNAME"_CleanupStatus" --type "String" --value "READY" --overwrite
    exit 1
}

# Enable EPEL repo
qs_enable_epel &> /var/log/userdata.qs_enable_epel.log

cd /tmp

# Installing Amazon SSM agent
qs_retry_command 10 wget https://s3-us-west-1.amazonaws.com/amazon-ssm-us-west-1/latest/linux_amd64/amazon-ssm-agent.rpm
rc=$?
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download amazon SSM agent file."
  cfn_init_status
fi
qs_retry_command 10 yum install -y ./amazon-ssm-agent.rpm
systemctl start amazon-ssm-agent
systemctl enable amazon-ssm-agent
rm -f ./amazon-ssm-agent.rpm

if [ ! -d "/usr/local/bin/" ]; then
  mkdir /usr/local/bin/
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] Couldn't create /usr/local/bin/ directory."
    cfn_init_status
  fi
fi

# Installing Red Hat Openshift 4.12 CLI
qs_retry_command 10 wget https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable-4.12/openshift-client-linux.tar.gz
rc=$?
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download Red Hat OpenShift CLI file."
  cfn_init_status
fi
tar -xvf openshift-client-linux.tar.gz
chmod -R 755 oc
chmod -R 755 kubectl
mv oc /usr/local/bin/oc
mv kubectl /usr/local/bin/kubectl
rm -f openshift-client-linux.tar.gz

# Installing Red Hat Openshift 4.12 installer
wget https://mirror.openshift.com/pub/openshift-v4/x86_64/clients/ocp/stable-4.12/openshift-install-linux.tar.gz
rc=$?
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download Red Hat OpenShift installer file."
  cfn_init_status
fi
tar -xvf openshift-install-linux.tar.gz
chmod 755 openshift-install
mv openshift-install /ibm
rm -f openshift-install-linux.tar.gz

cd ..

# Installing Docker CLI 19.x.x
wget https://download.docker.com/linux/static/stable/x86_64/docker-19.03.9.tgz
rc=$?
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download docker file."
  cfn_init_status
fi
tar -xvf docker-19.03.9.tgz 
cp docker/* /usr/local/bin/
dockerd &> /dev/null &
rm -f ./docker-19.03.9.tgz

# Testing Docker
ps -ef |grep docker
docker run hello-world

# Installing Cloud Pak CLI latest version
curl -L https://github.com/IBM/cloud-pak-cli/releases/latest/download/cloudctl-linux-amd64.tar.gz -o cloudctl-linux-amd64.tar.gz
rc=$?
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download cloudctl file."
  cfn_init_status
fi
tar -xvf cloudctl-linux-amd64.tar.gz
chmod 755 cloudctl-linux-amd64
mv cloudctl-linux-amd64 /usr/local/bin/cloudctl
rm -f cloudctl-linux-amd64.tar.gz

# Installing OpenSSL 1.1.1
yum install -y make gcc perl-core pcre-devel wget zlib-devel
wget https://ftp.openssl.org/source/openssl-1.1.1k.tar.gz
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download OpenSSL 1.1.1k file."
  cfn_init_status
fi
tar -xzvf openssl-1.1.1k.tar.gz
rm -f openssl-1.1.1k.tar.gz
cd openssl-1.1.1k
./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic
make
make test
make install
echo -e "export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64" >> /etc/profile.d/openssl.sh
source /etc/profile.d/openssl.sh
openssl version

# Installing jq
yum install wget
wget https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 -O /usr/local/bin/jq
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download jq file."
  cfn_init_status
fi
chmod 755 /usr/local/bin/jq

# Installing yq
wget https://github.com/mikefarah/yq/releases/download/3.4.0/yq_linux_386 -O /usr/local/bin/yq
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't download yq file."
  cfn_init_status
fi
chmod 755  /usr/local/bin/yq

# Installed boto3
qs_retry_command 10 pip install boto3 &> /var/log/userdata.boto3_install.log
if [ "$rc" != "0" ]; then
  failure_msg="[ERROR] Couldn't install boto3."
  cfn_init_status
fi

# Downloading Quick Start assets from s3 bucket

if [ -n "$GI_QS_S3URI" ]; then
  # Downloading Quick Start scripts from S3 bucket
  aws s3 cp ${GI_QS_S3URI}scripts/ /ibm/ --recursive
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] Quick Start scripts couldn't be downloaded from S3 bucket. Invalid S3 endpoint URI."
    cfn_init_status
  fi
fi

if [ -n "$INGRESS_KEYFILE_S3URI" ]; then
  # Downloading TLS certificate from S3 bucket
  aws s3 cp ${INGRESS_KEYFILE_S3URI} /ibm/tls/tls.crt
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] TLS certificate couldn't be downloaded from S3 bucket. Invalid S3 endpoint URI."
    cfn_init_status "$failure_msg"
  fi
fi

if [ -n "$INGRESS_CERTFILE_S3URI" ]; then
  # Downloading TLS certificate key from S3 bucket
  aws s3 cp ${INGRESS_CERTFILE_S3URI} /ibm/tls/tls.key
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] TLS certificate key couldn't be downloaded from S3 bucket. Invalid S3 endpoint URI."
    cfn_init_status "$failure_msg"
  fi
fi

if [ -n "$INGRESS_CAFILE_S3URI" ]; then
  # Downloading custom TLS certificate from S3 bucket
  aws s3 cp ${INGRESS_CAFILE_S3URI} /ibm/tls/ca.crt
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] Custom TLS certificate couldn't be downloaded from S3 bucket. Invalid S3 endpoint URI."
    cfn_init_status "$failure_msg"
  fi
fi

cd /ibm
if [ ! -d "${PWD}/logs" ]; then
  mkdir logs
  rc=$?
  if [ "$rc" != "0" ]; then
    failure_msg="[ERROR] Couldn't create ${PWD}/logs directory."
    cfn_init_status
  fi
fi

chmod 755 gi_install.py
chmod 755 /ibm/templates/gi/gi-custom-resource-xlarge.yaml
chmod 755 /ibm/templates/gi/gi-custom-resource.yaml
chmod 755 install.sh
chmod 755 change_cs_credentials.sh
chmod 755 install_utils.sh
chmod 755 destroy.sh

if [ -d "${PWD}/tls/" ]; then
  chmod -R 755 tls
fi

LOGFILE="${PWD}/logs/bootstrap.log"
echo $HOME
export KUBECONFIG=/root/.kube/config
echo $KUBECONFIG
echo $PATH

# Switching to python3
update-alternatives --install /usr/bin/python python /usr/bin/python3 1
sleep 15
python --version &> /var/log/userdata.python3_install.log

# Install pyyaml
pip3 install pyyaml

# Install Argparse
pip3 install argparse

python2 /ibm/gi_install.py --region "${AWS_REGION}" --stack-id "${AWS_STACKID}" --stack-name ${AWS_STACKNAME} --logfile $LOGFILE --loglevel "*=all"