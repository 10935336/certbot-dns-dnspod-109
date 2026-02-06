"""Tests for certbot_dns_dnspod_109._internal.dns_dnspod"""

import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


# Simulate Tencent Cloud API exception for delete-path robustness tests.
class MockApiException(Exception):
    pass


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, "file.ini")
        # This plugin version expects prefixed keys in credentials file.
        dns_test_common.write(
            {"dnspod_secret_id": "test_id", "dnspod_secret_key": "test_key"},
            path
        )

        self.config = mock.MagicMock(
            dnspod_credentials=path,
            dnspod_propagation_seconds=0,
        )

        self.auth = Authenticator(self.config, "dnspod")
        self.mock_client = mock.MagicMock()

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        with mock.patch.object(self.auth, "_get_dnspod_client", return_value=self.mock_client):
            self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record("_acme-challenge." + DOMAIN, mock.ANY, 600)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        with mock.patch.object(self.auth, "_get_dnspod_client", return_value=self.mock_client):
            self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record("_acme-challenge." + DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_no_creds(self):
        path = os.path.join(self.tempdir, "empty.ini")
        dns_test_common.write({}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])

    def test_missing_secret_id(self):
        path = os.path.join(self.tempdir, "no_id.ini")
        dns_test_common.write({"dnspod_secret_key": "test_key"}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])

    def test_missing_secret_key(self):
        path = os.path.join(self.tempdir, "no_key.ini")
        dns_test_common.write({"dnspod_secret_id": "test_id"}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])

    def test_get_dnspod_client_not_prepared(self):
        self.auth.credentials = None
        with pytest.raises(errors.Error):
            self.auth._get_dnspod_client()

    def test_get_dnspod_client_missing_required(self):
        creds = mock.MagicMock()
        creds.conf.side_effect = lambda k: {"dnspod_secret_id": "id_only"}.get(k)
        self.auth.credentials = creds
        with pytest.raises(errors.Error):
            self.auth._get_dnspod_client()

    def test_get_dnspod_client_default_endpoint(self):
        from certbot_dns_dnspod_109._internal import dns_dnspod as mod

        creds = mock.MagicMock()
        creds.conf.side_effect = lambda k: {
            "secret_id": "id",
            "secret_key": "key",
            "endpoint": None,
        }.get(k)

        self.auth.credentials = creds

        with mock.patch.object(mod, "_DnspodClient") as m_client_cls:
            self.auth._get_dnspod_client()
            m_client_cls.assert_called_once_with(
                secret_id="id",
                secret_key="key",
                endpoint="dnspod.tencentcloudapi.com",
            )

    def test_get_dnspod_client_custom_endpoint(self):
        from certbot_dns_dnspod_109._internal import dns_dnspod as mod

        creds = mock.MagicMock()
        creds.conf.side_effect = lambda k: {
            "secret_id": "id",
            "secret_key": "key",
            "endpoint": "custom.endpoint.tencentcloudapi.com",
        }.get(k)

        self.auth.credentials = creds

        with mock.patch.object(mod, "_DnspodClient") as m_client_cls:
            self.auth._get_dnspod_client()
            m_client_cls.assert_called_once_with(
                secret_id="id",
                secret_key="key",
                endpoint="custom.endpoint.tencentcloudapi.com",
            )


class DnspodClientTest(unittest.TestCase):
    record_name = "_acme-challenge." + DOMAIN
    record_content = "test_challenge"
    record_ttl = 600
    zone = DOMAIN
    subdomain = "_acme-challenge"
    record_id = 12345

    def setUp(self):
        from certbot_dns_dnspod_109._internal.dns_dnspod import _DnspodClient

        self.mock_dnspod_sdk_client = mock.MagicMock()

        # Patch SDK client constructor.
        patcher = mock.patch(
            "certbot_dns_dnspod_109._internal.dns_dnspod.dnspod_client.DnspodClient",
            return_value=self.mock_dnspod_sdk_client,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        # Patch request models used by the implementation.
        self.models_patcher = mock.patch("certbot_dns_dnspod_109._internal.dns_dnspod.models")
        self.mock_models = self.models_patcher.start()
        self.addCleanup(self.models_patcher.stop)

        self.CreateTXTRecordRequest = mock.MagicMock()
        self.DeleteRecordRequest = mock.MagicMock()
        self.DescribeRecordFilterListRequest = mock.MagicMock()
        self.DescribeDomainListRequest = mock.MagicMock()

        self.mock_models.CreateTXTRecordRequest.return_value = self.CreateTXTRecordRequest
        self.mock_models.DeleteRecordRequest.return_value = self.DeleteRecordRequest
        self.mock_models.DescribeRecordFilterListRequest.return_value = self.DescribeRecordFilterListRequest
        self.mock_models.DescribeDomainListRequest.return_value = self.DescribeDomainListRequest

        self.client = _DnspodClient(
            secret_id="test_id",
            secret_key="test_key",
            endpoint="dnspod.tencentcloudapi.com",
        )

    def test_normalize_fqdn(self):
        # Should strip trailing dots and lowercase.
        assert self.client._normalize_fqdn("WWW.Example.COM.") == "www.example.com"

    def test_to_ascii_fqdn_ascii_passthrough(self):
        # ASCII labels should remain unchanged except normalization.
        assert self.client._to_ascii_fqdn("WWW.Example.COM.") == "www.example.com"

    def test_to_ascii_fqdn_idn(self):
        # Non-ASCII labels should be IDNA-encoded.
        out = self.client._to_ascii_fqdn("www.例子.测试.")
        assert out == "www.xn--fsqu00a.xn--0zwm56d"

    def test_find_hosted_domain_exact_match(self):
        # Exact zone match should return ('zone', '@').
        self.client._list_all_domain = mock.MagicMock(return_value=["example.com"])
        zone, sub = self.client.find_hosted_domain("example.com.")
        assert zone == "example.com"
        assert sub == "@"

    def test_find_hosted_domain_parent_match(self):
        # Parent zone match should extract left part as subdomain.
        self.client._list_all_domain = mock.MagicMock(return_value=["example.com"])
        zone, sub = self.client.find_hosted_domain("_acme-challenge.example.com.")
        assert zone == "example.com"
        assert sub == "_acme-challenge"

    def test_find_hosted_domain_longest_suffix_wins(self):
        # Domains are expected to be sorted longest-first; ensure most specific zone is selected.
        self.client._list_all_domain = mock.MagicMock(return_value=["us.example.com", "example.com"])
        zone, sub = self.client.find_hosted_domain("_acme-challenge.us.example.com")
        assert zone == "us.example.com"
        assert sub == "_acme-challenge"

    def test_find_hosted_domain_not_found(self):
        self.client._list_all_domain = mock.MagicMock(return_value=["example.com"])
        with pytest.raises(errors.PluginError):
            self.client.find_hosted_domain("_acme-challenge.not-hosted.net")

    def test_list_all_domain_pagination_and_sort(self):
        # Build 2-page API responses and verify dedupe + normalization + sort-by-length-desc.
        d1 = mock.MagicMock()
        d1.Punycode = "Example.COM."
        d2 = mock.MagicMock()
        d2.Punycode = "us.example.com"
        d3 = mock.MagicMock()
        d3.Punycode = "example.com"  # duplicate after normalize
        d4 = mock.MagicMock()
        d4.Punycode = None  # should be skipped

        resp1 = mock.MagicMock()
        resp1.DomainList = [d1, d2]
        resp1.DomainCountInfo.DomainTotal = 4

        resp2 = mock.MagicMock()
        resp2.DomainList = [d3, d4]
        resp2.DomainCountInfo.DomainTotal = 4

        self.mock_dnspod_sdk_client.DescribeDomainList.side_effect = [resp1, resp2]

        zones = self.client._list_all_domain()
        assert zones == ["us.example.com", "example.com"]

    def test_add_txt_record(self):
        # Avoid testing zone lookup path here; isolate CreateTXTRecord request behavior.
        self.client.find_hosted_domain = mock.MagicMock(return_value=(self.zone, self.subdomain))

        mock_response = mock.MagicMock()
        mock_response.RecordId = self.record_id
        mock_response.RequestId = "mock_request_id"
        self.mock_dnspod_sdk_client.CreateTXTRecord.return_value = mock_response

        self.client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

        self.mock_dnspod_sdk_client.CreateTXTRecord.assert_called_once_with(self.CreateTXTRecordRequest)
        assert self.CreateTXTRecordRequest.Domain == self.zone
        assert self.CreateTXTRecordRequest.SubDomain == self.subdomain
        assert self.CreateTXTRecordRequest.Value == self.record_content
        assert self.CreateTXTRecordRequest.TTL == self.record_ttl
        assert self.CreateTXTRecordRequest.RecordLine == "默认"

    def test_add_txt_record_failed(self):
        self.client.find_hosted_domain = mock.MagicMock(return_value=(self.zone, self.subdomain))

        # Missing RecordId should be treated as failure.
        mock_response = mock.MagicMock()
        mock_response.RecordId = None
        self.mock_dnspod_sdk_client.CreateTXTRecord.return_value = mock_response

        with pytest.raises(errors.PluginError):
            self.client.add_txt_record(self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        self.client.find_hosted_domain = mock.MagicMock(return_value=(self.zone, self.subdomain))

        # _find_txt_record_id checks Name == subdomain and Value == content.
        mock_record = mock.MagicMock()
        mock_record.RecordId = self.record_id
        mock_record.Name = self.subdomain
        mock_record.Value = self.record_content

        mock_response = mock.MagicMock()
        mock_response.RecordList = [mock_record]
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        mock_del_response = mock.MagicMock()
        mock_del_response.RequestId = "del_request_id"
        self.mock_dnspod_sdk_client.DeleteRecord.return_value = mock_del_response

        self.client.del_txt_record(self.record_name, self.record_content)

        self.mock_dnspod_sdk_client.DescribeRecordFilterList.assert_called_once_with(
            self.DescribeRecordFilterListRequest
        )
        self.mock_dnspod_sdk_client.DeleteRecord.assert_called_once_with(self.DeleteRecordRequest)
        assert self.DeleteRecordRequest.RecordId == self.record_id
        assert self.DeleteRecordRequest.Domain == self.zone

    def test_del_txt_record_not_found(self):
        self.client.find_hosted_domain = mock.MagicMock(return_value=(self.zone, self.subdomain))

        mock_response = mock.MagicMock()
        mock_response.RecordList = []
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        # Not found should be a no-op.
        self.client.del_txt_record(self.record_name, self.record_content)
        self.mock_dnspod_sdk_client.DeleteRecord.assert_not_called()

    def test_del_txt_record_error(self):
        self.client.find_hosted_domain = mock.MagicMock(return_value=(self.zone, self.subdomain))

        mock_record = mock.MagicMock()
        mock_record.RecordId = self.record_id
        mock_record.Name = self.subdomain
        mock_record.Value = self.record_content
        mock_response = mock.MagicMock()
        mock_response.RecordList = [mock_record]
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        # del_txt_record should swallow exceptions and log errors.
        self.mock_dnspod_sdk_client.DeleteRecord.side_effect = MockApiException("Delete error")
        self.client.del_txt_record(self.record_name, self.record_content)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
