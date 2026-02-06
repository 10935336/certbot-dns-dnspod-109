"""DNS Authenticator for Dnspod."""
import logging
from typing import Any, List, Tuple
from typing import Callable
from typing import Optional

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Dnspod https://www.dnspod.cn/ (Tencent Cloud https://cloud.tencent.com/)

    This Authenticator uses the Dnspod API to fulfill a dns-01 challenge.
    """

    # required by certbot
    description = 'Obtain certificates using a DNS TXT record (if you are using Dnspod for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self.ACCOUNT_URL = 'https://console.cloud.tencent.com/cam'
        self.ttl = 600

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Dnspod credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
            'the Dnspod API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Dnspod credentials INI file',
            {
                'secret_id': f'Secret ID, from Tencent Cloud {self.ACCOUNT_URL}',
                'secret_key': f'Secret Key, from Tencent Cloud {self.ACCOUNT_URL}',
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnspod_client().add_txt_record(validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnspod_client().del_txt_record(validation_name, validation)

    def _get_dnspod_client(self) -> '_DnspodClient':
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared, did you set 'credentials'?")
        if self.credentials.conf('secret_id') and self.credentials.conf('secret_key'):
            return _DnspodClient(secret_id=self.credentials.conf('secret_id'),
                                 secret_key=self.credentials.conf('secret_key'),
                                 endpoint=self.credentials.conf('endpoint') or "dnspod.tencentcloudapi.com")
        else:
            raise errors.Error("Missing required credentials: secret_id and secret_key are required")


class _DnspodClient:
    """
    Encapsulates all communication with the Tencent Cloud API 3.0.
    """

    def __init__(self, secret_id: str, secret_key: str, endpoint: str = "dnspod.tencentcloudapi.com") -> None:
        # init Tencent Cloud SDK
        cred = credential.Credential(secret_id, secret_key)

        http_profile = HttpProfile()
        http_profile.endpoint = endpoint

        client_profile = ClientProfile()
        client_profile.httpProfile = http_profile

        self.client = dnspod_client.DnspodClient(cred, "", client_profile)

    @staticmethod
    def _normalize_fqdn(name: str) -> str:
        """
        Normalizes a fully qualified domain name (FQDN).

        This method is used to transform an input FQDN by stripping any trailing
        dots and converting the string to lowercase. This ensures uniformity
        and consistent handling of FQDNs for comparisons and other operations.

        Parameters:
        name: str
            The fully qualified domain name to normalize.

        Returns:
        str
            The normalized FQDN with trailing dots removed and all characters
            in lowercase.
        """
        return name.rstrip(".").lower()

    def _to_ascii_fqdn(self, fqdn: str) -> str:
        """
        Converts a fully qualified domain name (FQDN) to its ASCII representation.

        This method processes the provided FQDN to ensure it adheres to ASCII encoding
        standards. Non-ASCII labels are converted using IDNA encoding, while ASCII
        labels remain unchanged. Empty labels and invalid input are ignored during
        conversion.

        Parameters:
        fqdn: str
            The fully qualified domain name to be processed.

        Returns:
        str
            The ASCII-encoded version of the provided fully qualified domain name.
        """
        fqdn = self._normalize_fqdn(fqdn)
        labels = fqdn.split(".")
        out = []
        for lab in labels:
            if not lab:
                continue
            if all(ord(c) < 128 for c in lab):
                out.append(lab)
            else:
                out.append(lab.encode("idna").decode("ascii"))
        return ".".join(out)

    def find_hosted_domain(self, record_fqdn: str) -> Tuple[str, str]:
        """
        Determines the hosted domain and the subdomain part for a given fully qualified domain name (FQDN).

        The method searches the list of all hosted domains to find one that either matches exactly
        or is a parent domain to the provided FQDN. If found, it returns the hosted domain and the
        subdomain part of the FQDN. If no matching hosted domain is found, an exception is raised.

        Parameters:
            record_fqdn (str): The fully qualified domain name (FQDN) to search for.

        Returns:
            Tuple[str, str]: A tuple containing:
                - The hosted domain that covers the provided FQDN.
                - The subdomain part of the FQDN relative to the hosted domain
                  or "@" if the FQDN matches the hosted domain exactly.

        Raises:
            PluginError: If no hosted domain is found, that can cover the provided FQDN.
        """
        fqdn = self._to_ascii_fqdn(record_fqdn)
        domains = self._list_all_domain()

        for domain in domains:
            if fqdn == domain or fqdn.endswith("." + domain):
                if fqdn == domain:
                    sub = "@"
                else:
                    sub = fqdn[:-(len(domain) + 1)]
                return domain, sub

        raise errors.PluginError(
            f"Can't find a hosted domain that can cover {record_fqdn}. "
            f"Please make sure you have hosted the domain (e.g. example.com / us.example.com) in DNSPod."
        )

    def _list_all_domain(self) -> List[str]:
        """
        Fetches and returns a sorted list of all domains associated with the account.

        This method interacts with the API to retrieve a complete list of domains by
        iteratively querying the DescribeDomainList API endpoint. It normalizes and
        filters the retrieved domain data, ensuring that the list contains unique
        entries sorted in descending order by their length.

        Returns:
            List[str]: A sorted list of unique domain names.
        """
        zones: List[str] = []
        offset = 0
        limit = 3000  # default limit for DescribeDomainList API

        while True:
            req = models.DescribeDomainListRequest()
            req.Offset = offset
            req.Limit = limit
            resp = self.client.DescribeDomainList(req)

            domain_list = resp.DomainList or []
            for d in domain_list:
                if getattr(d, "Punycode", None):
                    zones.append(self._normalize_fqdn(d.Punycode))

            total = int(resp.DomainCountInfo.DomainTotal)
            offset += len(domain_list)
            if offset >= total or len(domain_list) == 0:
                break

        return sorted(set(zones), key=len, reverse=True)

    def add_txt_record(self, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Adds a TXT DNS record to the specified domain using the provided details.

        This function is responsible for creating a TXT type DNS record in the
        appropriate hosted zone identified by the given record name.

        Parameters:
        record_name (str): The full name of the record (e.g., "_acme-challenge.example.com").
        record_content (str): The value or content of the TXT record.
        record_ttl (int): The time-to-live (TTL) value for the record, dictating how long
                          it can be cached.

        Raises:
        PluginError: If the TXT record addition fails, typically due to an issue in
                     the response from the DNS provider.

        Notes:
        The function automatically determines the hosted domain and subdomain to
        target the correct DNS zone. A log entry is also created upon successful
        record addition with relevant details.
        """
        zone, subdomain = self.find_hosted_domain(record_name)

        req = models.CreateTXTRecordRequest()
        req.Domain = zone
        req.SubDomain = subdomain
        req.RecordLine = '默认'  # required
        req.Value = record_content
        req.TTL = record_ttl

        resp = self.client.CreateTXTRecord(req)

        record_id = getattr(resp, "RecordId", None)
        if not record_id:
            raise errors.PluginError(f"Failed to add TXT record, response: {resp}")
        logger.info(
            f"Successfully added TXT record: zone: {zone} sub: {subdomain} record_id: {record_id} request_id: {resp.RequestId}")

    def del_txt_record(self, record_name: str, record_content: str) -> None:
        """
        Deletes a TXT record from the DNS configuration.

        This method removes a specific TXT record from the DNS configuration associated with the given
        record name and record content. It identifies the domain and subdomain hosting the record,
        verifies its ID, and submits a request to delete it. In the event the record is not found or
        an error occurs during deletion, appropriate logging messages are generated.

        Parameters:
        record_name: str
            The fully qualified domain name (FQDN) of the TXT record to be deleted.
        record_content: str
            The content of the TXT record to be deleted.

        Raises:
            Exception: If an error occurs during record retrieval or deletion.
        """
        try:
            domain, subdomain = self.find_hosted_domain(record_name)
            record_id = self._find_txt_record_id(domain, subdomain, record_content)
            if not record_id:
                logger.warning("Record not found, skipping deletion: domain=%s sub=%s", domain, subdomain)
                return

            req = models.DeleteRecordRequest()
            req.Domain = domain
            req.RecordId = record_id
            resp = self.client.DeleteRecord(req)
            logger.info(
                f"Successfully deleted TXT record: domain: {domain} sub: {subdomain} request_id: {resp.RequestId}")
        except Exception as e:
            logger.error("Failed to delete TXT record: %s", e)

    def _find_txt_record_id(self, domain: str, subdomain: str, record_content: str) -> Optional[int]:
        """
        Find the ID of a TXT record that matches the specified domain name, subdomain,
        and record content.

        This method searches for an existing TXT record by domain, subdomain, and the
        record content within the list of records returned by the client. If a matching
        record is found, its ID is returned. If no match is found, None is returned.

        Parameters:
            domain: str
                The domain name in which to search for the TXT record.
            subdomain: str
                The subdomain name for the TXT record, typically the host or name
                portion of the record.
            record_content: str
                The text content of the TXT record that is being searched for.

        Returns:
            Optional[int]: The ID of the matching TXT record if found, otherwise None.
        """
        req = models.DescribeRecordFilterListRequest()
        req.Domain = domain
        req.SubDomain = subdomain
        req.RecordType = ["TXT"]

        resp = self.client.DescribeRecordFilterList(req)
        for r in (resp.RecordList or []):
            if r.Name == subdomain and r.Value == record_content:
                logger.info(f"Found TXT record for {r.Name}")
                return int(r.RecordId)

        logger.warning(f"No TXT record found for {subdomain}")
        return None
