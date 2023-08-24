#!/bin/bash

log_file="/ibm/logs/gi_install.log"
exec &> >(tee -a "$log_file")

export OCP_SERVER_URL=$1
export OCP_USERNAME=kubeadmin
export OCP_PASSWORD=$2
export LOCAL_CASE_DIR=$HOME/guardium-insights
export ICS_NAMESPACE=ibm-common-services
export ICS_SIZE=$3
export NAMESPACE=$4
export CP_REPO_USER=cp
export ADMIN_USERNAME=$5
export ADMIN_PASSWORD=$6
export DB2_SIZE=$7
export TAINT_DATA_NODE=$8
export CP_REPO_PASS=$9
export GI_VERSION=${10}
export GI_PRODUCTION_SIZE=${11}

if [ "$GI_VERSION" == "3.2.7" ]; then
  export CASE_VERSION="2.2.7"
  export CASE_ARCHIVE="ibm-guardium-insights-2.2.7.tgz"
elif [ "$GI_VERSION" == "3.2.6" ]; then
  export CASE_VERSION="2.2.6"
  export CASE_ARCHIVE="ibm-guardium-insights-2.2.6.tgz"
else
  echo "IBM Security Guardium Insights Version not supported. Exiting..."
  exit 1
fi

[[ $ADMIN_PASSWORD == "-" ]] && export ADMIN_PASSWORD=''

if [ -f "/ibm/tls/tls.crt" ]; then
  export INGRESS_KEYFILE="/ibm/tls/tls.crt"
else
  export INGRESS_KEYFILE="none"
fi
if [ -f "/ibm/tls/tls.key" ]; then
  export INGRESS_CERTFILE="/ibm/tls/tls.key"
else
  export INGRESS_CERTFILE="none"
fi
if [ -f "/ibm/tls/ca.crt" ]; then
  export INGRESS_CAFILE="/ibm/tls/ca.crt"
else
  export INGRESS_CAFILE="none"
fi

source install_utils.sh

# Logging in to the OCP cluster
echo "-------------------------"
echo "LOGGING IN TO THE CLUSTER"
echo "-------------------------"
oc login $OCP_SERVER_URL -u $OCP_USERNAME -p $OCP_PASSWORD --insecure-skip-tls-verify
# Checking exit status
rc=$?
success_msg="[SUCCESS] OpenShift cluster login successful. Logged in as $OCP_USERNAME."
error_msg="[ERROR] OpenShift cluster login failed."
check_exit_status

# Create local case directory for Guaridum Insights installation
printf "Creating local case directory for Guaridum Insights installation..."
mkdir $LOCAL_CASE_DIR
rc=$?
success_msg="[SUCCESS] Created $LOCAL_CASE_DIR directory successfully."
error_msg="[ERROR] Failed to create $LOCAL_CASE_DIR directory."
check_exit_status

# Downloading and extracting the IBM Security Guardium Insights case file
echo "------------------------------------------------------"
echo "DOWNLOADING AND EXTRACTING GUARDIUM INSIGHTS CASE FILE"
echo "------------------------------------------------------"
cloudctl case save \
  --case https://github.com/IBM/cloud-pak/raw/master/repo/case/ibm-guardium-insights/${CASE_VERSION}/${CASE_ARCHIVE} \
  --outputdir $LOCAL_CASE_DIR --tolerance 1
# Checking exit status
rc=$?
success_msg="[SUCCESS] Download and extracted IBM Security Guardium Insights CASE."
error_msg="[ERROR] Failed to download and extract IBM Security Guardium Insights CASE."
check_exit_status

# Create namespace for the Cloud Pak foundational services.
printf "Creating namespace for the Cloud Pak foundational services...\n"
oc create namespace $ICS_NAMESPACE
# Checking exit status
rc=$?
success_msg="[SUCCESS] Created namespace for the Cloud Pak foundational services."
error_msg="[ERROR] Failed to create namespace for the Cloud Pak foundational services."
check_exit_status

# Install the Cloud Pak foundational services catalog
echo "--------------------------------------------------"
echo "INSTALLING CLOUD PAK FOUNDATIONAL SERVICES CATALOG"
echo "--------------------------------------------------"
cloudctl case launch \
  --case ${LOCAL_CASE_DIR}/${CASE_ARCHIVE} \
  --namespace $ICS_NAMESPACE \
  --inventory ibmCommonServiceOperatorSetup \
  --action install-catalog \
  --tolerance 1 \
  --args "--registry icr.io --inputDir ${LOCAL_CASE_DIR}"
# Checking exit status
rc=$?
if [ "$rc" != "0" ]; then
  error_msg="[ERROR] Failed to Install the Cloud Pak foundational services catalog."
  check_exit_status
fi

# Checking opencloud operators pods status
printf "\n"
sleep 30
maxRetry=5
for ((retry=0;retry<=${maxRetry};retry++));
do
    status=$(oc get pods -n openshift-marketplace | grep opencloud-operators | awk '{ print $3 }')
    ready=$(oc get pods -n openshift-marketplace | grep opencloud-operators | awk '{ print $2 }')
    if [[ $status == 'Running' && $ready == '1/1' ]]; then
        printf "[SUCCESS] opencloud-operators pod created successfully.\n\n"
        oc get pods -n openshift-marketplace | grep opencloud-operators
        printf "\n"
        break
    else
        if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] Failed to create opencloud-operators pod.\n"
          exit 1
        else
          printf "INFO - Waiting for opencloud-operators pod to be created.\n"
          sleep 60
          continue
        fi
    fi
done

# Checking opencloud operators catalog source status
printf "\n"
maxRetry=5
for ((retry=0;retry<=${maxRetry};retry++));
do
    catalog_source_name=$(oc get catalogsource -n openshift-marketplace | grep opencloud-operators | awk '{ print $1 }')
    if [[ $catalog_source_name == 'opencloud-operators' ]]
    then
      printf "[SUCCESS] opencloud-operators catalog source created successfully.\n\n"
      oc get catalogsource -n openshift-marketplace | grep opencloud-operators
      printf "\n"
      break
    else
        if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] Failed to create opencloud-operators catalog source. \n"
          exit 1
        else
          printf "INFO - Waiting for opencloud-operators catalog source to be created.\n"
          sleep 60
          continue
        fi
    fi
done

# Install the Cloud Pak foundational services operators
echo "----------------------------------------------------"
echo "INSTALLING CLOUD PAK FOUNDATIONAL SERVICES OPERATORS"
echo "----------------------------------------------------"
cloudctl case launch \
  --case ${LOCAL_CASE_DIR}/${CASE_ARCHIVE} \
  --namespace ${ICS_NAMESPACE} \
  --inventory ibmCommonServiceOperatorSetup \
  --tolerance 1 \
  --action install-operator \
  --args "--size ${ICS_SIZE} --inputDir ${LOCAL_CASE_DIR}"
# Checking exit status
rc=$?
if [ "$rc" != "0" ]; then
  error_msg="[ERROR] Failed to install the Cloud Pak foundational services operators."
  check_exit_status
fi

# Checking Cloud Pak foundational services pods status
printf "\n"
sleep 60
maxRetry=10
flag=true
for ((retry=0;retry<=${maxRetry};retry++));
do
  ibm_common_services_status=$(oc get pods -n ibm-common-services | awk 'NR!=1 { print $3 }')
  pods_status=($ibm_common_services_status)
  for pod_status in "${pods_status[@]}"
  do
    if [[ $pod_status == 'Running' || $pod_status == 'Completed' ]]
    then
      flag=true
      continue
    else
      flag=false
      break
    fi
  done
  if $flag
  then
      printf "[SUCCESS] Cloud Pak foundational services pods created succussfully.\n\n"
      oc get pods -n ibm-common-services
      printf "\n"
      break
  else
      if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] Failed to create Cloud Pak foundational services pod(s). \n"
          exit 1
      else
          printf "INFO - Waiting for Cloud Pak foundational services pods to be created.\n"
          sleep 180
          continue
      fi
  fi
done

# Changing IBM Common Services platform-auth-idp-credentials
echo "----------------------------------------------------------"
echo "CHANGING IBM COMMON SERVICES PLATFORM-AUTH-IDP-CREDENTIALS"
echo "----------------------------------------------------------"
printf "Changing IBM Common Services platform-auth-idp-credentials.\n"
if [[ ! -z "$ADMIN_PASSWORD" ]]; then
  echo "INFO - Changing ICS Admin Username and Password"
  bash change_cs_credentials.sh -u ${ADMIN_USERNAME} -p ${ADMIN_PASSWORD}
else
  echo "INFO - Changing ICS Admin Username"
  bash change_cs_credentials.sh -u ${ADMIN_USERNAME}
fi
# Checking exit status
rc=$?
success_msg="[SUCCESS] Changed IBM Common Services platform-auth-idp-credentials."
error_msg="[ERROR] Failed to change IBM Common Services platform-auth-idp-credentials."
check_exit_status

sleep 60

# Create namespace for the Guardium Insights instance.
printf "Creating namespace for the Guardium Insights instance...\n"
oc create namespace $NAMESPACE
# Checking exit status
rc=$?
success_msg="[SUCCESS] Created namespace for the Guardium Insights instance."
error_msg="[ERROR] Failed to create namespace for the Guardium Insights instance."
check_exit_status

# Retrieve host names of the data nodes for data computation
nodes=$(oc get nodes --show-labels | grep db2-data-node |cut -d' ' -f1) 
printf "Guardium Insights nodes that will used as dedicated DB2 data nodes:\n"
printf "${nodes}\n\n"
db2_data_nodes=($nodes); db2_data_nodes_list=""; no_of_nodes=$DB2_SIZE; node=0
while [ $node -lt $no_of_nodes ]
do
   db2_data_nodes_list+="${db2_data_nodes[$node]},"
   node=`expr $node + 1`
done
db2_data_nodes_list=${db2_data_nodes_list::-1}
if [[ -z "$db2_data_nodes_list" ]]; then
  echo "[ERROR] Failed to retrieve Guardium Insights nodes that will used as dedicated DB2 data nodes."
  exit 1
fi

# Install the Guardium Insights operator and related components
echo "------------------------------------------------------------"
echo "INSTALLING GUARDIUM INSIGHTS OPERATOR AND RELATED COMPONENTS"
echo "------------------------------------------------------------"
cloudctl case launch    \
  --case ${LOCAL_CASE_DIR}/${CASE_ARCHIVE} \
  --namespace ${NAMESPACE} \
  --inventory install     \
  --action pre-install    \
  --tolerance 1 \
  --args "-n ${NAMESPACE} -h ${db2_data_nodes_list} -l true -t ${TAINT_DATA_NODE} -k ${INGRESS_KEYFILE} -f ${INGRESS_CERTFILE} -c ${INGRESS_CAFILE}"
# Checking exit status
rc=$?
success_msg="[SUCCESS] Installed the Guardium Insights operator and related components."
error_msg="[ERROR] Failed to install the Guardium Insights operator and related components."
check_exit_status

# Install the Guardium Insights catalogs
echo "-------------------------------------"
echo "INSTALLING GUARDIUM INSIGHTS CATALOGS"
echo "-------------------------------------"
cloudctl case launch \
  --case ${LOCAL_CASE_DIR}/${CASE_ARCHIVE} \
  --namespace openshift-marketplace \
  --inventory install \
  --action install-catalog \
  --args "--inputDir ${LOCAL_CASE_DIR}" \
  --tolerance 1
# Checking exit status
rc=$?
if [ "$rc" != "0" ]; then
  error_msg="[ERROR] Failed to install the Guardium Insights catalogs."
  check_exit_status
fi

# Verfiy that the catalogs are installed
printf "\n"
sleep 30
maxRetry=10
for ((retry=0;retry<=${maxRetry};retry++));
do
    redis_operator_status=$(oc get pods -n openshift-marketplace | grep ibm-cloud-databases-redis-operator-catalog | awk '{ print $3 }')
    redis_operator_ready=$(oc get pods -n openshift-marketplace | grep ibm-cloud-databases-redis-operator-catalog | awk '{ print $2 }')
    db2_operator_status=$(oc get pods -n openshift-marketplace | grep ibm-db2uoperator-catalog | awk '{ print $3 }')
    db2_operator_ready=$(oc get pods -n openshift-marketplace | grep ibm-db2uoperator-catalog | awk '{ print $2 }')
    if [[ $redis_operator_status == 'Running' && $db2_operator_status == 'Running' && $redis_operator_ready == '1/1' && $db2_operator_ready == '1/1' ]]
    then
      printf "[SUCCESS] Guardium Insights catalogs created successfully.\n\n"
      oc get pods -n openshift-marketplace|grep ibm-cloud-databases-redis-operator-catalog
      oc get pods -n openshift-marketplace | grep ibm-db2uoperator-catalog
      printf "\n"
      break
    else
        if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] Failed to create Guardium Insights catalogs.\n"
          exit 1
        else
          printf "INFO - Waiting for Guardium Insights catalogs to be created.\n"
          sleep 90
          continue
        fi
    fi
done

# Install the Guardium Insights operators
echo "--------------------------------------"
echo "INSTALLING GUARDIUM INSIGHTS OPERATORS"
echo "--------------------------------------"
cloudctl case launch \
  --case ${LOCAL_CASE_DIR}/${CASE_ARCHIVE} \
  --namespace ${NAMESPACE} \
  --inventory install \
  --action install-operator \
  --tolerance 1 \
  --args "--registry cp.icr.io --user ${CP_REPO_USER} --pass ${CP_REPO_PASS} --secret ibm-entitlement-key"
# Checking exit status
rc=$?
if [ "$rc" != "0" ]; then
  error_msg="[ERROR] Failed to install the Guardium Insights operators."
  check_exit_status
fi

# Verfiy that the operators are installed
printf "\n"
sleep 30
maxRetry=10
for ((retry=0;retry<=${maxRetry};retry++));
do
    gi_controller_manager_status=$(oc get pods | grep guardiuminsights-controller-manager | awk '{ print $3 }')
    gi_controller_manager_ready=$(oc get pods | grep guardiuminsights-controller-manager | awk '{ print $2 }')
    redis_operator_status=$(oc get pods | grep ibm-cloud-databases-redis-operator | awk '{ print $3 }')
    redis_operator_ready=$(oc get pods | grep ibm-cloud-databases-redis-operator | awk '{ print $2 }')
    mongodb_operator_status=$(oc get pods | grep mongodb-kubernetes-operator | awk '{ print $3 }')
    mongodb_operator_ready=$(oc get pods | grep mongodb-kubernetes-operator | awk '{ print $2 }')
    if [[ $gi_controller_manager_status == 'Running' && $redis_operator_status == 'Running' && $mongodb_operator_status == 'Running' && $gi_controller_manager_ready == '1/1' && $redis_operator_ready == '1/1' && $mongodb_operator_ready == '1/1' ]]
    then
      printf "[SUCCESS] Guardium Insights operators created successfully.\n\n"
      oc get pods | grep guardiuminsights-controller-manager
      oc get pods | grep ibm-cloud-databases-redis-operator
      oc get pods | grep mongodb-kubernetes-operator
      printf "\n"
      break
    else
        if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] Failed to create Guardium Insights operators.\n"
          exit 1
        else
          printf "INFO - Waiting for Guardium Insights operators to be created.\n"
          sleep 90
          continue
        fi
    fi
done

# List available StorageClasses
echo "---------------"
echo "STORAGE CLASSES"
echo "---------------"
oc get storageclass
printf "\n"
sleep 10

# Create the Guardium Insights instance using custom resource(CR)
echo "---------------------------------------------------------"
echo "CREATING GUARDIUM INSIGHTS INSTANCE USING CUSTOM RESOURCE"
echo "---------------------------------------------------------"
if [[ ${GI_PRODUCTION_SIZE} == "xlarge" ]]; then
  oc create -f /ibm/templates/gi/gi-custom-resource-xlarge.yaml
else
  oc create -f /ibm/templates/gi/gi-custom-resource.yaml
fi
# Checking exit status
rc=$?
success_msg="[INFO] Guardium Insights instance creation in progress..."
error_msg="[ERROR] Failed to create Guardium Insights instance using custom resource(CR)."
check_exit_status
sleep 30

# Check the status of the instance creation
maxRetry=30
for ((retry=0;retry<=${maxRetry};retry++));
do
    oc get guardiuminsights
    type=$(oc get guardiuminsights -o=jsonpath='{.items[*].status.conditions[0].type}')
    if [[ $type == 'Ready' ]]; then
      printf "\n"
      echo "-----------------------------------------------------"
      echo "IBM Security Guardium Insights Installed Successfully"
      echo "-----------------------------------------------------"
      printf "\n"
      break
    else
        if [[ $retry -eq ${maxRetry} ]]; then
          printf "\n[ERROR] Timed Out! Failed to create Guardium Insights instance using custom resource(CR).\n\n"
          oc get pods
          exit 1
        elif [[ $type == 'Failure' ]]; then
          printf "\n[ERROR] Failed to create Guardium Insights instance using custom resource(CR).\n\n"
          oc get pods
          exit 1
        else
          sleep 180
          continue
        fi
    fi
done

# Check PVC status
maxRetry=5
flag=true
for ((retry=0;retry<=${maxRetry};retry++));
do
  pvcs=$(oc get pvc -o jsonpath='{.items[*].status.phase}')
  pvc_status=($pvcs)
  for status in "${pvc_status[@]}"
  do
    if [[ $status == 'Bound' ]]
    then
      flag=true
      continue
    else
      flag=false
      break
    fi
  done
  if $flag
  then
      printf "[SUCCESS] PVCs has Bound status.\n"
      oc get pvc
      break
  else
      if [[ $retry -eq ${maxRetry} ]]; then
          printf "[ERROR] PVC(s) failed to have Bound status. \n"
          exit 1
      else
          printf "INFO - Waiting for all PVCs status to be Bound.\n"
          sleep 180
          continue
      fi
  fi
done

# Cleanup secrets from the EC2 instance
cleanup_secrets