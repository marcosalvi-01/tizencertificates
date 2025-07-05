# first initialize the certificates
python cert_server.py --device-id="H3CDNTGI3OI76" --email="1marco.salvi@gmail.com" --cert-password=foobar --tv

# here you will have to login with your samsung account

# then cd in the cert dir and run the container:

cd certificates
docker run --rm -v "$(pwd)/author.p12":/certificates/author.p12 -v "$(pwd)/distributor.p12":/certificates/distributor.p12 ghcr.io/georift/install-jellyfin-tizen 192.168.1.103 Jellyfin "" 'foobar'

cd ..
