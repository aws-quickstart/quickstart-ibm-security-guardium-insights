
# IBM Security Guardium Insights - AWS Quick Start

#### Required items

- Red Hat pull secret
- IBM private registry (cp.icr.io) password (Entitlement key)
- Key pair for Amazon EC2
- Server Certificate and Key for IBM Security Guardium Insights Fully Qualified Domain Name (FQDN) (optional)

**Where can I get my RedHat pull-secret from?**
Visit: https://cloud.redhat.com/openshift/install/aws/installer-provisioned

**Where can I get my IBM private registry password?**
Visit: https://myibm.ibm.com/products-services/containerlibrary

**How can I create a key pair for Amazon EC2?**
Visit: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair

#### Part 1. Setup resources

**Set-up EC2 Key pair**
From your AWS dashboard (ensure you're in the correct region)
Find Services: EC2 > Network & Security > Key Pairs > Create key pair

**How do I use my key pair to SSH into the BootNode instance?**

When you generate a key pair you should recieve a *\*.pem* file containing the private key. With this you can simply use the *-i* option with *ssh* to login.

```bash
ssh -i path_to_key/key.pem ec2-user@BootNode_instance_ip
```

Where the *path_to_key/key.pem* is where you downloaded your private key and *BootNode_instance_ip* is the public IPv4 address of the BootNode instance.

**Set-up your own S3 Bucket to store the files needed for installation.**

You need to create an S3 bucket in one of the AWS Regions. See https://docs.aws.amazon.com/AmazonS3/latest/userguide/creating-bucket.html

To know how to upload files into your S3 bucket, see https://docs.aws.amazon.com/AmazonS3/latest/userguide/uploading-an-object-bucket.html

This S3 bucket is used for storing Red Hat OpenShift pull secret, TLS certificates and keys(optional) and SOAR Entitlement(optional) required for {partner-product-name} deployment.

#### Part 2. Stack deployment

There are 3 stacks involved with this Quick Start.

1. Root stack - Takes in user input from parameters
2. VPC stack - Creates VPC infrastructure for OpenShift
3. Guardium Insights stack - Creates EC2 instance, downloads resources, and runs bootstrap.sh 

#### Part 3. Bootstrap

The *bootstrap.sh* script is essentially the entrypoint for the Quick Start deployment of the product. It's responsible for installing all dependecies onto the BootNode, modifying permissions and file system, and finally calling the installation of the product with gi_install.py.

#### Part 4. Installation of the product

When bootstrapping is complete all depndencies needed to run automation to deploy the desired product should be in place. From here the bootstrap will run the products automation to deploy. First OpenShift is installed using the openshift-install IPI followed by IBM Cloud Pak foundational services and Guardium Insights using in-house built automation.

#### Part 5. Logging

Check logs in output s3 bucket or in the Boot node EC2 instance.

**/ibm/logs/ocp_install.log** - STDOUT of the deployment of Red Hat OpenShift Container Platform using IPI.

**/ibm/logs/gi_install.log** - STDOUT of the deployment of installing IBM Cloud Pak foundational services and IBM Security Guardium Insights including the validation of the installation.

**/ibm/logs/bootstrap.log** - STDOUT of the high overview of the events during deployment of Red Hat OpenShift Container Platform and IBM Security Guardium Insights.  
