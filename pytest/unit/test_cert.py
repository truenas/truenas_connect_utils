from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from truenas_connect_utils.cert import generate_csr, get_hostnames_from_hostname_config


def test_csr_requests_server_auth_only():
    # Public CAs no longer issue client auth for TLS server certs and Google rejects requests which ask for it
    csr, _ = generate_csr(get_hostnames_from_hostname_config('example.com'))
    eku = x509.load_pem_x509_csr(csr.encode()).extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH]
