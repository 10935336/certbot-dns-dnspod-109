"""DNS Authenticator for Dnspod."""
import logging
from typing import Any
from typing import Callable
from typing import Optional

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

from tencentcloud.common import credential
from tencentcloud.dnspod.v20210323 import dnspod_client, models

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Dnspod https://www.dnspod.cn/ (Tencent Cloud https://cloud.tencent.com/)

    This Authenticator uses the Dnspod API to fulfill a dns-01 challenge.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self.description = 'Obtain certificates using a DNS TXT record (if you are using Dnspod for DNS).'
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
        self._get_dnspod_client().add_txt_record(domain, validation_name, validation, self.ttl)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_dnspod_client().del_txt_record(domain, validation_name, validation)

    def _get_dnspod_client(self) -> "_DnspodClient":
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared, did you set 'credentials'?")
        if self.credentials.conf('secret_id') and self.credentials.conf('secret_key'):
            return _DnspodClient(secret_id=self.credentials.conf('secret_id'),
                                 secret_key=self.credentials.conf('secret_key'),
                                 endpoint=self.credentials.conf('endpoint') or "https://dnspod.tencentcloudapi.com")


class _DnspodClient:
    """
    Encapsulates all communication with the Tencent Cloud API 3.0.
    """

    def __init__(self, secret_id: str, secret_key: str, endpoint: str) -> None:
        # Use Tencent Cloud SDK
        cred = credential.Credential(secret_id, secret_key)
        self.client = dnspod_client.DnspodClient(cred, "")

    def add_txt_record(self, domain: str, record_name: str, record_content: str, record_ttl: int) -> None:
        """
        Add a TXT record using the supplied information.

        :param domain: The domain to use to look up the DNS zone.
        :param record_name: The record name (typically '_acme-challenge.').
        :param record_content: The record content (typically the challenge validation string).
        :param record_ttl: The record TTL in seconds.
        """
        logger.info(f"Adding TXT record for {record_name}")

        req = models.CreateTXTRecordRequest()
        req.Domain = domain
        req.RecordLine = '默认'  # required
        req.Value = record_content
        req.TTL = record_ttl
        req.SubDomain = record_name.split(".")[0]

        response = self.client.CreateTXTRecord(req)
        record_id = response.RequestId

        if not record_id:
            raise Exception(f"Failed to add TXT record: {response}")
        logger.info(f"Successfully added TXT record: {record_id}")

    def del_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """
        Delete a TXT record using the supplied information.

        :param domain: The domain to use to look up the DNS zone.
        :param record_name: The record name (typically '_acme-challenge.').
        :param record_content: The record content (typically the challenge validation string).
        """
        try:
            logger.info("Deleting TXT record for %s", record_name)

            record_id = self._find_txt_record_id(domain, record_name, record_content)
            if not record_id:
                logger.warning("Record not found, skipping deletion.")
                return

            req = models.DeleteRecordRequest()
            req.Domain = domain
            req.RecordId = record_id

            response = self.client.DeleteRecord(req)
            if response.RequestId:
                logger.info(f"Successfully deleted TXT record: {record_id}, RequestId ID: {response.RequestId}")
        except Exception as e:
            logger.error(f"Failed to delete TXT record: {e}")

    def _find_txt_record_id(self, domain: str, record_name: str, record_content: str) -> Optional[int]:
        """
        Find the record ID for a TXT record with the given name and content.

        :param domain: The domain to use to look up the DNS zone.
        :param record_name: The record name (typically '_acme-challenge.').
        :param record_content: The record content (typically the challenge validation string).
        :returns: The record ID, if found.
        """
        logger.info(f"Searching for TXT record for {record_name}")

        req = models.DescribeRecordFilterListRequest()
        req.Domain = domain
        req.SubDomain = record_name.split(".")[0]
        req.RecordType = ["TXT"]

        response = self.client.DescribeRecordFilterList(req)
        records = response.RecordList

        for record in records:
            if record.Name == record_name.split(".")[0] and record.Value == record_content:
                logger.info(f"Found TXT record for {record.Name}")
                return record.RecordId

        logger.warning(f"No TXT record found for {record_name}")
        return None
