# Keycloak / Databricks SSO Integration

## Optional: build and run the Keycloak Docker image
```
cd docker
./build.sh
```
The run.sh script is provided to be used at the first startup.

### Integrate Keycloak with Apache
You can find a template for the Keycloak virtualhost file in docker/virtualhost.conf.template. 
Lines containing FIXME need configuration. Use a certificate signed by an authority, 
self-signed certificates will give trouble, running without SSL is highly discouraged.

## Provision a realm in Keycloak
Create a file called keycloak.local.yaml as a copy from keycloak.yaml and configure all values. 
The keycloak_password value should be set to the same value as provided at first run.
Make sure a realm with the name configure in keycloak_realm does not exist already or else an error 409 will be raised.
Now run the provisioning script:
```
virtualenv venv --python python3
. venv/bin/activate
pip install --upgrade pip
cd provision
pip install -r requirements.txt
python keycloak.py
```
It will output all necessary values to configure Databricks

## Configure Databricks

