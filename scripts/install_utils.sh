#!/bin/bash

#Function to check exit status
check_exit_status() {
   printf "\n"
   if [ "$rc" != "0" ];
   then
      echo $error_msg
      printf "\n"
      exit 1
   else
      echo $success_msg
      printf "\n"
      return
   fi
}

#Function to validate TLS Certificates & Key
check_dns() {
  printf "\n[INFO] - Validating TLS certificates and key.\n"
  if [ -z "$INGRESS_KEYFILE" ]; then
    if [ -n "$INGRESS_CAFILE" ]; then
       printf "[ERROR] Custom TLS certificate is provided but no TLS certificate.\n"
       exit 1
    fi
    if [ -n "$INGRESS_CERTFILE" ]; then
       printf "[ERROR] TLS key is provided but no TLS certificate.\n"
       exit 1
    fi
    printf "\n[INFO] The TLS certificate associated with the Guardium Insights application domain is not provided. Default would be used.\n"
    return
  fi

  if [ ! -f "$INGRESS_KEYFILE" ]; then
     printf "[ERROR] TLS certificate file $INGRESS_KEYFILE not found.\n"
     exit 1
  fi
  if [ -z "$INGRESS_CERTFILE" ]; then
     printf "[ERROR] TLS key file not set.\n"
     exit 1
  fi
  if [ ! -f "$INGRESS_CERTFILE" ]; then
     printf "[ERROR] TLS key file $INGRESS_CERTFILE  not found.\n"
     exit 1
  fi
  if [ -z "$INGRESS_CAFILE" ]; then
     return
  fi
  if [ ! -f "$INGRESS_CAFILE" ]; then
     printf "[ERROR] Custom TLS certificate file $INGRESS_CAFILE not found.\n"
     exit 1
  fi
  return
}

#Function to delete all secrets after stack completion
cleanup_secrets() {
   if [ -d "/ibm/tls/" ]; then
      sudo rm -rf /ibm/tls
   fi
   if [ -f "/ibm/pull-secret" ]; then
      sudo rm -f /ibm/pull-secret
   fi
   printf "\nCleanup complete, deleted all secrets from the EC2 instance!\n"
   return
}