#!/usr/bin/python

# standard library imports
import base64
import json
import os.path
from os import chmod, environ
import shutil
import socket
import stat
from subprocess import check_output, check_call, CalledProcessError #nosec
import sys
import time

# third party imports
import boto3
from botocore.exceptions import ClientError

# local library imports
import yapl.Utilities as Utilities
from yapl.Trace import Trace, Level
from yapl.LogExporter import LogExporter
from yapl.Exceptions import MissingArgumentException, InvalidParameterException

TR = Trace(__name__)
StackParameters = {}
StackParameterNames = []


class GuardiumInsightsInstall(object):
    args_signature = {
                    '--region': 'string',
                    '--stack-name': 'string',
                    '--stack-id': 'string',
                    '--logfile': 'string',
                    '--loglevel': 'string',
                    '--trace': 'string'
                   }

    def __init__(self):
        """
        Constructor
        NOTE: Some instance variable initialization happens
        in self._init (which is invoked early in main() at some
        point after _get_stack_parameters().
        """
        object.__init__(self)
        self.home = os.path.expanduser("/ibm")
        self.logs_home = os.path.join(self.home, "logs")
    # endDef

    def _get_arg(self, synonyms, args, default=None):
        """
        Return the value from the args dictionary that may be specified with
        any of the argument names in the list of synonyms.
        The synonyms argument may be a Jython list of strings or it may be a
        string representation of a list of names with a comma or space
        separating each name.
        The args is a dictionary with the keyword value pairs that are the
        arguments that may have one of the names in the synonyms list.
        If the args dictionary does not include the option that may be named
        by any of the given synonyms then the given default value is returned.

        NOTE: This method has to be careful to make explicit checks for value
        being None rather than something that is just logically false.
        If value gets assigned 0 from the get on the args (command line args)
        dictionary, that appears as false in a condition expression.
        However 0 may be a legitimate value for an input parameter in the args
        dictionary. We need to break out of the loop that is checking
        synonyms as well as avoid assigning the default value if 0 is the
        value provided in the args dictionary.
        """
        value = None
        if (type(synonyms) != type([])):
            synonyms = Utilities.splitString(synonyms)
        # endIf

        for name in synonyms:
            value = args.get(name)
            if value is not None:
                break
        # endIf
        # endFor

        if value is None and default is not None:
            value = default
        # endIf

        return value
    # endDef

    def _configure_trace_and_logging(self, traceArgs):
        """
        Return a tuple with the trace spec and logFile if trace is set based
        on given traceArgs.

        traceArgs is a dictionary with the trace configuration specified.
            loglevel|trace <tracespec>
            logfile|logFile <pathname>

        If trace is specified in the trace arguments then set up the trace.
        If a log file is specified, then set up the log file as well.
        If trace is specified and no log file is specified, then the log file
        is set to "trace.log" in the current working directory.
        """
        logFile = self._get_arg(['logFile', 'logfile'], traceArgs)
        if logFile:
            TR.appendTraceLog(logFile)
        # endIf

        trace = self._get_arg(['trace', 'loglevel'], traceArgs)

        if trace:
            if (not logFile):
                TR.appendTraceLog('trace.log')
            # endDef

        TR.configureTrace(trace)
        # endIf
        return (trace, logFile)
    # endDef

    def get_stack_parameters(self, stack_id):
        """
        Return a dictionary with stack parameter name-value pairs from the
        CloudFormation stack with the given stack_id.
        """
        result = {}
        stack = self.cfnResource.Stack(stack_id)
        stackParameters = stack.parameters
        for parm in stackParameters:
            parmName = parm['ParameterKey']
            parmValue = parm['ParameterValue']
            result[parmName] = parmValue
        # endFor
        return result
    # endDef

    def __getattr__(self, attributeName):
        """
        Support for attributes that are defined in the StackParameterNames
        list and with values in the StackParameters dictionary.
        """
        attributeValue = None
        if attributeName in StackParameterNames:
            attributeValue = StackParameters.get(attributeName)
        else:
            raise AttributeError("%s is not a StackParameterName" % attributeName)
        # endIf

        return attributeValue
    # endDef

    def __setattr__(self, attributeName, attributeValue):
        """
        Support for attributes that are defined in the StackParameterNames
        list and with values in the StackParameters dictionary.

        NOTE: The StackParameters are intended to be read-only.  It's not
        likely they would be set in the Bootstrap instance once they are
        initialized in _get_stack_parameters().
        """
        if attributeName in StackParameterNames:
            StackParameters[attributeName] = attributeValue
        else:
            object.__setattr__(self, attributeName, attributeValue)
        # endIf
    # endDef

    def print_time(self, begin_time, end_time, text):
        """
        Method to capture time elapsed for each event during installation.
        """
        method_name = "print_time"
        elapsed_time = (end_time - begin_time)/1000
        etm, ets = divmod(elapsed_time, 60)
        eth, etm = divmod(etm, 60)
        TR.info(method_name, "Elapsed time (hh:mm:ss): %d:%02d:%02d for %s" % (eth, etm, ets, text))
    # endDef

    def update_template_file(self, source, placeholder, value):
        """
        Method to update placeholder values in templates
        """
        source_file = open(source).read()
        source_file = source_file.replace(placeholder, value)
        updated_file = open(source, 'w')
        updated_file.write(source_file)
        updated_file.close()
    # endDef

    def read_file_content(self, source):
        file = open(source, mode='r')
        content = file.read()
        file.close()
        return content.rstrip()
    # endDef

    def install_ocp(self, ocp_install_log_file):
        method_name = "install_ocp"
        TR.info(method_name, "Start installation of Openshift Container Platform")

        installConfigFile = "/ibm/installDir/install-config.yaml"
        autoScalerFile = "/ibm/templates/gi/machine-autoscaler.yaml"
        healthcheckFile = "/ibm/templates/gi/health-check.yaml"

        icf_1az = "/ibm/installDir/install-config-1AZ.yaml"
        asf_1az = "/ibm/templates/gi/machine-autoscaler-1AZ.yaml"
        hc_1az = "/ibm/templates/gi/health-check-1AZ.yaml"

        if len(self.availability_zones) == 1:
            shutil.copyfile(icf_1az, installConfigFile)
            shutil.copyfile(asf_1az, autoScalerFile)
            shutil.copyfile(hc_1az, healthcheckFile)
        # endIf

        self.update_template_file(installConfigFile, '${az1}', self.availability_zones[0])
        self.update_template_file(installConfigFile, '${baseDomain}', self.DomainName)
        self.update_template_file(installConfigFile, '${master-instance-type}', self.MasterInstanceType)
        self.update_template_file(installConfigFile, '${master-instance-count}', self.NumberOfMaster)
        self.update_template_file(installConfigFile, '${worker-instance-type}', self.GINodeInstanceType)
        self.update_template_file(installConfigFile, '${worker-instance-count}', self.NumberOfGINodes)
        self.update_template_file(installConfigFile, '${region}', self.region)
        self.update_template_file(installConfigFile, '${subnet-1}', self.PrivateSubnet1ID)
        self.update_template_file(installConfigFile, '${subnet-2}', self.PublicSubnet1ID)
        self.update_template_file(installConfigFile, '${pullSecret}', self.read_file_content(self.pull_secret_path))
        self.update_template_file(installConfigFile, '${sshKey}', self.read_file_content("/root/.ssh/id_rsa.pub"))
        self.update_template_file(installConfigFile, '${clustername}', self.ClusterName)
        self.update_template_file(installConfigFile, '${machine-cidr}', self.VPCCIDR)
        self.update_template_file(autoScalerFile, '${az1}', self.availability_zones[0])
        self.update_template_file(healthcheckFile, '${az1}', self.availability_zones[0])

        TR.info(method_name, "Initiating installation of Openshift Container Platform")
        os.chmod("/ibm/openshift-install", stat.S_IEXEC)
        install_ocp_cmd = "sudo ./openshift-install create cluster --dir=/ibm/installDir --log-level=debug"
        TR.info(method_name, "Output File name: %s" % ocp_install_log_file)
        try:
            check_call(['bash', '-c', install_ocp_cmd], stdout=ocp_install_log_file, stderr=ocp_install_log_file)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}".format(e.cmd, e.returncode))
            raise e
        TR.info(method_name, "Installed Openshift Container Platform")
        time.sleep(30)

        dest_dir = "/root/.kube"
        if (not os.path.exists(dest_dir)):
            os.makedirs(dest_dir)
        shutil.copyfile("/ibm/installDir/auth/kubeconfig", "/root/.kube/config")
        self.ocpassword = self.read_file_content("/ibm/installDir/auth/kubeadmin-password").rstrip("\n\r")
        self.logincmd = "oc login -u kubeadmin -p " + self.ocpassword
        try:
            check_call(['bash', '-c', self.logincmd])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}".format(e.cmd, e.returncode))
            raise e
        get_clusterId = r"oc get machineset -n openshift-machine-api -o jsonpath='{.items[0].metadata.labels.machine\.openshift\.io/cluster-api-cluster}'"
        TR.info(method_name, "Get cluster ID %s" % get_clusterId)
        try:
            self.clusterID = check_output(['bash', '-c', get_clusterId])
            TR.info(method_name, "Cluster ID %s" % self.clusterID)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e

        time.sleep(30)
        TR.info(method_name, "Creating Db2 data nodes")
        workerdb2 = "/ibm/templates/gi/workerdb2.yaml"

        self.update_template_file(workerdb2, '${az1}', self.availability_zones[0])
        self.update_template_file(workerdb2, '${ami_id}', self.ami_id)
        self.update_template_file(workerdb2, '${instance-type}', self.Db2DataNodeInstanceType)
        self.update_template_file(workerdb2, '${instance-count}', self.NumberOfDb2DataNodes)
        self.update_template_file(workerdb2, '${region}', self.region)
        self.update_template_file(workerdb2, '${cluster-name}', self.ClusterName)
        self.update_template_file(workerdb2, 'CLUSTERID', self.clusterID)
        self.update_template_file(workerdb2, '${subnet-1}', self.PrivateSubnet1ID)

        create_db2_data_nodes_cmd = "oc create -f " + workerdb2
        try:
            retcode = check_output(['bash', '-c', create_db2_data_nodes_cmd])
            time.sleep(600)
            TR.info(method_name, "Created Db2 data nodes %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e

        db2_data_nodes = []
        get_db2_data_nodes = "oc get nodes --show-labels | grep db2-data-node |cut -d' ' -f1"
        try:
            db2_data_nodes = check_output(['bash', '-c', get_db2_data_nodes])
            nodes = db2_data_nodes.split("\n")
            TR.info(method_name, "Db2 data nodes %s" % nodes)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e

        self.update_template_file(autoScalerFile, 'CLUSTERID', self.clusterID)
        create_machine_as_cmd = "oc create -f "+autoScalerFile
        TR.info(method_name, "Creating Machine autoscaler")
        try:
            retcode = check_output(['bash', '-c', create_machine_as_cmd])
            TR.info(method_name, "Created Machine autoscaler %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e

        self.update_template_file(healthcheckFile, 'CLUSTERID', self.clusterID)
        create_healthcheck_cmd = "oc create -f "+healthcheckFile
        TR.info(method_name, "Creating Machine Health Check")
        try:
            retcode = check_output(['bash', '-c', create_healthcheck_cmd])
            TR.info(method_name, "Created Machine Health check %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e

        TR.info(method_name, "Create OCP registry")

        registry_mc = "/ibm/templates/gi/insecure-registry.yaml"
        registries = "/ibm/templates/gi/registries.conf"
        crio_conf = "/ibm/templates/gi/crio.conf"
        crio_mc = "/ibm/templates/gi/crio-mc.yaml"
        route = "default-route-openshift-image-registry.apps."+self.ClusterName+"."+self.DomainName
        self.update_template_file(registries, '${registry-route}', route)
        config_data = base64.b64encode(self.read_file_content(registries))
        self.update_template_file(registry_mc, '${config-data}', config_data)
        crio_config_data = base64.b64encode(self.read_file_content(crio_conf))
        self.update_template_file(crio_mc, '${crio-config-data}', crio_config_data)
        route_cmd = "oc patch configs.imageregistry.operator.openshift.io/cluster --type merge -p '{\"spec\":{\"defaultRoute\":true,\"replicas\":"+self.NumberOfAZs+"}}'"
        TR.info(method_name, "Creating route with command %s" % route_cmd)
        try:
            retcode = check_output(['bash', '-c', route_cmd])
            TR.info(method_name, "Created route with command %s returned %s" % (route_cmd, retcode))
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e

        dest_dir = "/etc/containers/"
        if (not os.path.exists(dest_dir)):
            os.makedirs(dest_dir)
        shutil.copyfile(registries, "/etc/containers/registries.conf")
        create_registry = "oc create -f "+registry_mc
        create_crio_mc = "oc create -f "+crio_mc
        TR.info(method_name, "Creating registry mc with command %s" % create_registry)
        try:
            reg_retcode = check_output(['bash', '-c', create_registry])
            TR.info(method_name, "Creating crio mc with command %s" % create_crio_mc)
            crio_retcode = check_output(['bash', '-c', create_crio_mc])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        TR.info(method_name, "Created regsitry with command %s returned %s" % (create_registry, reg_retcode))
        TR.info(method_name, "Created Crio mc with command %s returned %s" % (create_crio_mc, crio_retcode))
        create_cluster_as_cmd = "oc create -f /ibm/templates/gi/cluster-autoscaler.yaml"
        TR.info(method_name, "Creating Cluster autoscaler")
        try:
            retcode = check_output(['bash', '-c', create_cluster_as_cmd])
            TR.info(method_name, "Created Cluster autoscaler %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        """
        "oc create -f ${local.ocptemplates}/wkc-sysctl-mc.yaml",
        "oc create -f ${local.ocptemplates}/security-limits-mc.yaml",
        """
        sysctl_cmd = "oc create -f /ibm/templates/gi/wkc-sysctl-mc.yaml"
        TR.info(method_name, "Create SystemCtl Machine config")
        try:
            retcode = check_output(['bash', '-c', sysctl_cmd])
            TR.info(method_name, "Created SystemCtl Machine config %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e

        secLimits_cmd = "oc create -f /ibm/templates/gi/security-limits-mc.yaml"
        TR.info(method_name, "Create Security Limits Machine config")
        try:
            retcode = check_output(['bash', '-c', secLimits_cmd])
            TR.info(method_name, "Created Security Limits Machine config %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        time.sleep(600)

        oc_route_cmd = "oc get route console -n openshift-console | grep 'console' | awk '{print $2}'"
        TR.info(method_name, "Get OC URL")
        try:
            self.openshift_url = check_output(['bash', '-c', oc_route_cmd])
            TR.info(method_name, "OC URL retrieved %s" % self.openshift_url)
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        TR.info(method_name, "Completed installation of Openshift Container Platform")
    # endDef

    def configure_ocs(self, ocp_install_log_file):
        """
        This method reads user preferences from stack parameters and
        configures OCS as storage classes accordingly.
        """
        method_name = "configure_ocs"
        TR.info(method_name, "Start configuration of OpenShift Container Storage for Guardium Insights")
        workerocs = "/ibm/templates/ocs/workerocs.yaml"

        self.update_template_file(workerocs, '${az1}', self.availability_zones[0])
        self.update_template_file(workerocs, '${ami_id}', self.ami_id)
        self.update_template_file(workerocs, '${instance-type}', self.OCSInstanceType)
        self.update_template_file(workerocs, '${instance-count}', self.NumberOfOCS)
        self.update_template_file(workerocs, '${region}', self.region)
        self.update_template_file(workerocs, '${cluster-name}', self.ClusterName)
        self.update_template_file(workerocs, 'CLUSTERID', self.clusterID)
        self.update_template_file(workerocs, '${subnet-1}', self.PrivateSubnet1ID)

        create_ocs_nodes_cmd = "oc create -f " + workerocs
        TR.info(method_name, "Creating OpenShift Container Storage nodes")
        try:
            retcode = check_output(['bash', '-c', create_ocs_nodes_cmd])
            time.sleep(600)
            TR.info(method_name, "Created OpenShift Container Storage nodes %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e

        ocs_nodes = []
        get_ocs_nodes = "oc get nodes --show-labels | grep storage-node |cut -d' ' -f1"
        try:
            ocs_nodes = check_output(['bash', '-c', get_ocs_nodes])
            nodes = ocs_nodes.split("\n")
            TR.info(method_name, "OpenShift Container Storage nodes %s" % nodes)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e

        deploy_olm_cmd = "oc create -f /ibm/templates/ocs/deploy-with-olm.yaml"
        TR.info(method_name, "Deploying OpenShift Lifecycle Manager")
        try:
            retcode = check_output(['bash', '-c', deploy_olm_cmd])
            time.sleep(300)
            TR.info(method_name, "Deployed OpenShift Lifecycle Manager %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e
        create_storage_cluster_cmd = "oc create -f /ibm/templates/ocs/ocs-storagecluster.yaml"
        TR.info(method_name, "Creating Storage Cluster")
        try:
            retcode = check_output(['bash', '-c', create_storage_cluster_cmd])
            time.sleep(60)
            TR.info(method_name, "Created Storage Cluster %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e
        install_ceph_tool_cmd = "curl -s https://raw.githubusercontent.com/rook/rook/release-1.7/cluster/examples/kubernetes/ceph/toolbox.yaml|sed 's/namespace: rook-ceph/namespace: openshift-storage/g'| oc apply -f -"
        TR.info(method_name, "Installing ceph toolkit")
        try:
            retcode = check_output(['bash', '-c', install_ceph_tool_cmd])
            TR.info(method_name, "Installed ceph toolkit %s" % retcode)
        except CalledProcessError as e:
            TR.error(method_name, "command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            raise e
        TR.info(method_name, "Completed configuring OpenShift Container Storage for Guardium Insights")
    # endDef

    def install_gi(self, ocp_install_log_file):
        method_name = "install_gi"
        TR.info(method_name, "Starting installation of IBM Security Guardium Insights")
        gi_cr_file = "/ibm/templates/gi/gi-custom-resource.yaml"
        self.LicenseType = self.LicenseType.split(" ", 1)[0]
        self.ocp_server_url = "api."+self.ClusterName+"."+self.DomainName+":6443"  #nosec
        if self.admin_password == "":  #nosec
            self.admin_password = "-"  #nosec
        self.db2_size = self.NumberOfDb2DataNodes
        self.taint_data_node = "true"
        if self.GIProductionSize == "xsmall":
            self.db2_memory = "48Gi"
            self.ics_size = "small"
            self.taint_data_node = "false"
        elif self.GIProductionSize == "small":
            self.db2_memory = "48Gi"
            self.ics_size = "small"
        elif self.GIProductionSize == "med":
            self.db2_memory = "110Gi"
            self.ics_size = "medium"
        else:
            self.db2_memory = "220Gi"
            self.ics_size = "large"
        TR.info(method_name, "Updating Guardium Insights custom resource file")
        self.update_template_file(gi_cr_file, '${namespace}', self.Namespace)
        self.update_template_file(gi_cr_file, '${version}', self.GIVersion)
        self.update_template_file(gi_cr_file, '${license-type}', self.LicenseType)
        self.update_template_file(gi_cr_file, '${production-size}', self.GIProductionSize)
        self.update_template_file(gi_cr_file, '${db2-memory}', self.db2_memory)
        self.update_template_file(gi_cr_file, '${host-name}', self.HostName)
        self.update_template_file(gi_cr_file, '${domain-name}', self.DomainName)
        self.update_template_file(gi_cr_file, '${storage-class-rwo}', self.StorageClassRWO)
        self.update_template_file(gi_cr_file, '${storage-class-rwx}', self.StorageClassRWX)
        TR.info(method_name, "Updated Guardium Insights custom resource file")

        install_gi_cmd = (
            "bash install.sh" +
            " " + self.ocp_server_url +
            " " + self.ocpassword +
            " " + self.ics_size +
            " " + self.Namespace +
            " " + self.AdminUsername +
            " " + self.admin_password +
            " " + self.db2_size +
            " " + self.taint_data_node +
            " " + self.repository_password)
        TR.info(method_name, "Output File name: '/ibm/logs/gi_install.log'")
        try:
            TR.info(method_name, "Initiating installation of IBM Security Guardium Insights")
            check_call(['bash', '-c', install_gi_cmd])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}".format(e.cmd, e.returncode))
            raise e
        get_admin_username = "oc -n ibm-common-services get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_username}' | base64 -d"
        try:
            self.admin_username = check_output(['bash', '-c', get_admin_username])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        get_admin_password = "oc -n ibm-common-services get secret platform-auth-idp-credentials -o jsonpath='{.data.admin_password}' | base64 -d"  #nosec
        try:
            self.admin_password = check_output(['bash', '-c', get_admin_password])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        TR.info(method_name, "Completed installation of IBM Security Guardium Insights")
        # retrieve Guardium Insights host name
        get_hostname = r"oc get guardiuminsights -o=jsonpath='{.items[*].status.hostName}'"
        try:
            self.gi_host_name = check_output(['bash', '-c', get_hostname])
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
        TR.info(method_name, "Guardium Insights Host Name: %s" % (self.gi_host_name))
    # endDef

    def __init(self, stack_id, stack_name, ocp_install_log_file):
        method_name = "_init"
        global StackParameters, StackParameterNames
        boto3.setup_default_session(region_name=self.region)
        self.cfnResource = boto3.resource('cloudformation', region_name=self.region)
        self.cf = boto3.client('cloudformation', region_name=self.region)
        self.ec2 = boto3.client('ec2', region_name=self.region)
        self.s3 = boto3.client('s3', region_name=self.region)
        self.iam = boto3.client('iam', region_name=self.region)
        self.secretsmanager = boto3.client('secretsmanager', region_name=self.region)
        self.ssm = boto3.client('ssm', region_name=self.region)

        StackParameters = self.get_stack_parameters(stack_id)
        StackParameterNames = StackParameters.keys()
        TR.info(method_name, "self.stackParameters %s" % StackParameters)
        TR.info(method_name, "self.stackParameterNames %s" % StackParameterNames)
        self.log_exporter = LogExporter(
            region=self.region,
            bucket=self.GIDeploymentLogsBucketName,
            keyPrefix=stack_name,
            fqdn=socket.getfqdn())

        TR.info(method_name, "Creating SSH keys")
        command = "ssh-keygen -P {}  -f /root/.ssh/id_rsa".format("''")
        try:
            check_call(['bash', '-c', command], stdout=ocp_install_log_file)
            TR.info(method_name, "Created SSH keys")
        except CalledProcessError as e:
            TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
            raise e
    # endDef

    def get_secret(self, ocp_install_log_file):
        method_name = "get_secret"
        TR.info(method_name, "Start getting secrets from AWS Secrets Manager%")

        TR.info(method_name, "Retrieving secret %s" % self.gi_secret)
        secret_response = self.secretsmanager.get_secret_value(SecretId=self.gi_secret)
        if 'SecretString' in secret_response:
            secret_value = secret_response['SecretString']
            secret_dict = json.loads(secret_value)
            self.repository_password = secret_dict['repositoryPassword']
            self.admin_password = secret_dict['adminPassword']

        TR.info(method_name, "End getting secrets from AWS Secrets Manager")
    # endDef

    def update_secret(self, ocp_install_log_file):
        method_name = "update_secret"
        TR.info(method_name, "Start updating secrets in AWS Secrets Manager%")

        TR.info(method_name, "Updating secret %s" % self.ocp_secret)
        secret_update_oc = '{"ocpPassword": "' + self.ocpassword + '"}'
        response = self.secretsmanager.update_secret(SecretId=self.ocp_secret, SecretString=secret_update_oc)
        TR.info(method_name, "Updated secret for %s with response %s" % (self.ocp_secret, response))

        TR.info(method_name, "Updating secret %s" % self.gi_admin_secret)
        secret_update_gi = '{"adminPassword": "' + self.admin_password + '"}'
        response = self.secretsmanager.update_secret(SecretId=self.gi_admin_secret, SecretString=secret_update_gi)
        TR.info(method_name, "Updated secret for %s with response %s" % (self.gi_admin_secret, response))

        TR.info(method_name, "End updating secrets in AWS Secrets Manager")
    # endDef

    def export_result(self, name, parameter_value, ocp_install_log_file):
        method_name = "export_result"
        TR.info(method_name, "Start exporting result")
        self.ssm.put_parameter(
            Name=name,
            Value=parameter_value,
            Type='String',
            Overwrite=True)
        TR.info(method_name, "Value: %s put to: %s." % (parameter_value, name))
    # endDef

    def main(self, argv):
        method_name = "main"
        self.rc = 0
        try:
            begin_time = Utilities.currentTimeMillis()
            cmd_args = Utilities.getInputArgs(self.args_signature, argv[1:])
            trace, log_file = self._configure_trace_and_logging(cmd_args)
            self.region = cmd_args.get('region')
            if log_file:
                TR.appendTraceLog(log_file)
            if trace:
                TR.info(method_name, "Tracing with specification: '%s' to log file: '%s'" % (trace, log_file))

            log_file_path = os.path.join(self.logs_home, "ocp_install.log")
            with open(log_file_path, "a+") as ocp_install_log_file:
                self.stack_id = cmd_args.get('stack-id')
                self.stack_name = cmd_args.get('stack-name')
                self.ami_id = environ.get('AMI_ID')
                self.gi_secret = environ.get('GI_SECRET')
                self.ocp_secret = environ.get('OCP_SECRET')
                self.gi_admin_secret = environ.get('GI_ADMIN_SECRET')
                self.GIInstallationCompletedURL = environ.get('GIInstallationCompletedURL')
                TR.info(method_name, "AMI_ID %s " % self.ami_id)
                TR.info(method_name, "GIInstallationCompletedURL %s " % self.GIInstallationCompletedURL)
                TR.info(method_name, "GI_SECRET %s " % self.gi_secret)
                TR.info(method_name, "OCP_SECRET %s " % self.ocp_secret)
                TR.info(method_name, "GI_ADMIN_SECRET %s " % self.gi_admin_secret)
                self.__init(self.stack_id, self.stack_name, ocp_install_log_file)
                self.availability_zones = Utilities.splitString(self.AvailabilityZones)
                TR.info(method_name, "Availability Zones %s" % self.availability_zones)

                # copy Red Hat pull secret from Amazon S3
                TR.info(method_name, "Red Hat pull secret Amazon S3 URI %s" % self.RedhatPullSecret)  #nosec
                self.pull_secret_path = "/ibm/pull-secret"  #nosec
                s3_cp_cmd = "aws s3 cp " + self.RedhatPullSecret + " " + self.pull_secret_path  #nosec
                TR.info(method_name, "Copying Red Hat pull secret %s" % s3_cp_cmd)
                try:
                    check_call(['bash', '-c', s3_cp_cmd], stdout=ocp_install_log_file)
                    TR.info(method_name, "Copied Red Hat pull secret successfully to path %s" % self.pull_secret_path)
                except CalledProcessError as e:
                    TR.error(method_name, "[ERROR] Command '{}' returned non-zero exit status {}: {}".format(e.cmd, e.returncode, e.output))
                    raise e
                # retrieve the secrets from AWS Secrets Manager
                self.get_secret(ocp_install_log_file)

                # install OpenShift Container Platform
                ocp_start = Utilities.currentTimeMillis()
                self.install_ocp(ocp_install_log_file)
                ocp_end = Utilities.currentTimeMillis()
                self.print_time(ocp_start, ocp_end, "Installing OpenShift Container Platform")
                time.sleep(30)

                # configure OpenShift Container Storage
                if(self.StorageType == 'OCS'):
                    storage_start = Utilities.currentTimeMillis()
                    self.configure_ocs(ocp_install_log_file)
                    storage_end = Utilities.currentTimeMillis()
                    self.print_time(storage_start, storage_end, "Configuring OpenShift Container Storage")
                time.sleep(30)

                # install IBM Security Guaridum Insights
                gi_start = Utilities.currentTimeMillis()
                self.install_gi(ocp_install_log_file)
                gi_end = Utilities.currentTimeMillis()
                self.print_time(gi_start, gi_end, "Installing IBM Security Guardium Insights")
                time.sleep(30)

                # export OpenShift web console URL
                self.export_result(self.stack_name + "-OpenShiftURL", "https://" + self.openshift_url, ocp_install_log_file)
                # export Guardium Insights web client URL
                self.export_result(self.stack_name + "-GuaridumInsightsURL", "https://" + self.gi_host_name, ocp_install_log_file)
                # export Guardium Insights admin username
                self.export_result(self.stack_name + "-AdminUser", self.admin_username, ocp_install_log_file)

                # update the secrets in AWS Secrets Manager
                self.update_secret(ocp_install_log_file)
            # endWith

        except Exception as e:
            TR.error(method_name, "Exception with message %s" % e)
            self.rc = 1
        finally:
            try:
                # copy logs to the Guardium Insights deployment logs s3 bucket.
                self.log_exporter.exportLogs("/var/log/")
                self.log_exporter.exportLogs("%s" % self.logs_home)
            except Exception as e:
                TR.error(method_name, "[ERROR] Can't copy logs to S3 bucket: %s" % e, e)
                self.rc = 1

        end_time = Utilities.currentTimeMillis()
        elapsed_time = (end_time - begin_time)/1000
        etm, ets = divmod(elapsed_time, 60)
        eth, etm = divmod(etm, 60)

        if self.rc == 0:
            success = 'true'
            status = 'SUCCESS'
            TR.info(method_name, "SUCCESS END IBM Security Guardium Insights Install AWS GI Quickstart.  Elapsed time (hh:mm:ss): %d:%02d:%02d" % (eth, etm, ets))
        else:
            success = 'false'
            status = 'FAILURE: Check logs in the Guardium Insights deployment logs S3 bucket or on the Boot node EC2 instance in /ibm/logs/bootstrap.log /ibm/logs/ocp_install.log and /ibm/logs/gi_install.log'
            TR.info(method_name, "FAILED END IBM Security Guardium Insights Install AWS GI Quickstart.  Elapsed time (hh:mm:ss): %d:%02d:%02d" % (eth, etm, ets))
        # endIf

        try:
            data = "%s: IBM Security Guardium Insights installation elapsed time: %d:%02d:%02d" % (status, eth, etm, ets)
            check_call([
                'cfn-signal',
                '--success', success,
                '--id', self.stack_id,
                '--reason', status,
                '--data', data,
                self.GIInstallationCompletedURL])
        except CalledProcessError as e:
            TR.error(method_name, "ERROR return code: %s, Exception: %s" % (e.returncode, e), e)
            raise e
    # endDef
# endClass

if __name__ == '__main__':
    main_instance = GuardiumInsightsInstall()
    main_instance.main(sys.argv)
# endIf
