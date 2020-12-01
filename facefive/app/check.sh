#!/bin/sh

MY_IP=10.74.0.100

# Check if current folder exists
if [ ! -d "auth" ]; then
    mkdir auth
fi

cd auth
# Check for CA certificate
if [ ! -f "CA.cert" ]; then
    echo "Getting CA certificate"
    curl --fail -k https://ca:5000/CACert > CA.cert 2> /dev/null
    if [ $? -ne 0 ]; then
        echo "Couldn't get CA certificate"
        exit 1
    fi
    echo "Trusting CA certificate"
    cat CA.cert >> /usr/local/lib/python3.7/site-packages/certifi/cacert.pem
fi

gen=false
# Check for private key
if [ ! -f "FaceFive.key" ]; then
    gen=true
    echo "Generating private key"
    openssl genrsa -out FaceFive.key 2> /dev/null
fi

# Check for certificate
if [ ! -f "FaceFive.cert" ] || [ "$gen" = "true" ]; then
    echo "Generating CSR"
    openssl req -new -subj /O=FaceFive/subjectAltName=$MY_IP,webapp_app,webapp/CN=WebApp/ -key FaceFive.key -out /tmp/csr 2> /dev/null
    echo "Getting cert"
    curl --fail --cacert CA.cert --capath . -F csr=@/tmp/csr https://ca:5000/sign > FaceFive.cert 2> /dev/null
    if [ $? -ne 0 ]; then
        echo "Couldn't generate certificate"
        exit 1
    fi
fi

# Check for Auth certificate
while [ ! -f "AUTH.cert" ]; do
    echo "Getting AUTH certificate"
    curl --fail --cacert CA.cert --capath . https://ca:5000/cert/AUTH > AUTH.cert 2> /dev/null
    if [ $? -ne 0 ]; then
        echo "Waiting for AUTH cert to be available"
        rm AUTH.cert
        sleep 5
    fi
done

cd ..

