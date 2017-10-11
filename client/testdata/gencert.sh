# generate ca.pem and ca-key.pem
cfssl gencert -initca ca_csr.json |cfssljson -bare ca
# generate client.pem and client-key.pem
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config signing.json -profile client csr.json |cfssljson -bare client
# generate server.pem and server-key.pem
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config signing.json -profile server csr.json |cfssljson -bare server
# generate tls.pem and tls-key.pem
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config signing.json csr.json |cfssljson -bare tls
rm *.csr
