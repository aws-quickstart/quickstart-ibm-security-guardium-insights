#!/bin/bash
echo $1

sudo /ibm/openshift-install destroy cluster --dir=/ibm/installDir --log-level=info
aws ssm put-parameter \
    --name $1"_CleanupStatus" \
    --type "String" \
    --value "READY" \
    --overwrite