"""Tests for certbot_certbot_dns_dnspod_109._internal.dns_dnspod"""

import sys
import unittest
from unittest import mock

import pytest

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util


# Simulate the exception returned by Tencent Cloud Dnspod API to test error handling
class MockApiException(Exception):
    pass


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):

    def setUp(self):
        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator

        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({"dnspod_secret_id": "test_id", "dnspod_secret_key": "test_key"}, path)

        self.config = mock.MagicMock(dnspod_credentials=path,
                                     dnspod_propagation_seconds=0)  # Don't wait for actual records to take effect in tests

        self.auth = Authenticator(self.config, "dnspod")

        self.mock_client = mock.MagicMock()
        # Mock _get_dnspod_client
        self.auth._get_dnspod_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        # Test whether the perform method calls add_txt_record correctly
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_cleanup(self):
        # Test that the cleanup method calls del_txt_record correctly
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        assert expected == self.mock_client.mock_calls

    def test_no_creds(self):
        # Test that an exception is thrown when correct credentials are not provided
        path = os.path.join(self.tempdir, 'empty.ini')
        dns_test_common.write({}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])

    def test_missing_secret_id(self):
        # Test whether an exception is thrown when no credentials are provided
        path = os.path.join(self.tempdir, 'no_id.ini')
        dns_test_common.write({"secret_key": "test_key"}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])

    def test_missing_secret_key(self):
        # Test whether an exception is thrown when no credentials are provided
        path = os.path.join(self.tempdir, 'no_key.ini')
        dns_test_common.write({"secret_id": "test_id"}, path)
        self.config.dnspod_credentials = path

        from certbot_dns_dnspod_109._internal.dns_dnspod import Authenticator
        auth = Authenticator(self.config, "dnspod")
        with pytest.raises(errors.PluginError):
            auth.perform([self.achall])


class DnspodClientTest(unittest.TestCase):
    record_name = "_acme-challenge"
    record_content = "test_challenge"
    record_ttl = 600
    domain = DOMAIN
    record_id = 12345

    def setUp(self):
        from certbot_dns_dnspod_109._internal.dns_dnspod import _DnspodClient
        # Create a simulated dnspod_client
        self.mock_dnspod_client = mock.MagicMock()
        self.mock_credential = mock.MagicMock()
        self.mock_dnspod_sdk_client = mock.MagicMock()

        # Patch dnspod_client.DnspodClient constructor returns mock_dnspod_sdk_client
        patcher = mock.patch('certbot_dns_dnspod_109._internal.dns_dnspod.dnspod_client.DnspodClient',
                             return_value=self.mock_dnspod_sdk_client)
        patcher.start()
        self.addCleanup(patcher.stop)

        # Patch models module
        self.models_patcher = mock.patch('certbot_dns_dnspod_109._internal.dns_dnspod.models')
        self.mock_models = self.models_patcher.start()
        self.addCleanup(self.models_patcher.stop)

        self.CreateTXTRecordRequest = mock.MagicMock()
        self.DeleteRecordRequest = mock.MagicMock()
        self.DescribeRecordFilterListRequest = mock.MagicMock()

        self.mock_models.CreateTXTRecordRequest.return_value = self.CreateTXTRecordRequest
        self.mock_models.DeleteRecordRequest.return_value = self.DeleteRecordRequest
        self.mock_models.DescribeRecordFilterListRequest.return_value = self.DescribeRecordFilterListRequest

        self.client = _DnspodClient(secret_id="test_id", secret_key="test_key",
                                    endpoint="https://dnspod.tencentcloudapi.com")

    def test_add_txt_record(self):
        # Simulate the return of a successful RequestId when adding a record
        mock_response = mock.MagicMock()
        mock_response.RequestId = "mock_request_id"
        self.mock_dnspod_sdk_client.CreateTXTRecord.return_value = mock_response

        self.client.add_txt_record(self.domain, self.record_name, self.record_content, self.record_ttl)
        self.mock_dnspod_sdk_client.CreateTXTRecord.assert_called_once_with(self.CreateTXTRecordRequest)

        # Check if the request parameters are correctly assigned
        assert self.CreateTXTRecordRequest.Domain == self.domain
        assert self.CreateTXTRecordRequest.Value == self.record_content
        assert self.CreateTXTRecordRequest.TTL == self.record_ttl
        assert self.CreateTXTRecordRequest.SubDomain == self.record_name

    def test_add_txt_record_failed(self):
        # Simulate adding records and return no RequestId
        mock_response = mock.MagicMock()
        mock_response.RequestId = ""
        self.mock_dnspod_sdk_client.CreateTXTRecord.return_value = mock_response

        with pytest.raises(Exception):
            self.client.add_txt_record(self.domain, self.record_name, self.record_content, self.record_ttl)

    def test_del_txt_record(self):
        # Simulate the return of matching records when searching for record IDs
        mock_record = mock.MagicMock()
        mock_record.RecordId = self.record_id
        mock_record.Name = self.record_name
        mock_record.Value = self.record_content
        mock_response = mock.MagicMock()
        mock_response.RecordList = [mock_record]
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        # Simulate the success of deleting records
        mock_del_response = mock.MagicMock()
        mock_del_response.RequestId = "del_request_id"
        self.mock_dnspod_sdk_client.DeleteRecord.return_value = mock_del_response

        self.client.del_txt_record(self.domain, self.record_name, self.record_content)

        self.mock_dnspod_sdk_client.DescribeRecordFilterList.assert_called_once_with(
            self.DescribeRecordFilterListRequest)
        self.mock_dnspod_sdk_client.DeleteRecord.assert_called_once_with(self.DeleteRecordRequest)

        assert self.DeleteRecordRequest.RecordId == self.record_id
        assert self.DeleteRecordRequest.Domain == self.domain

    def test_del_txt_record_not_found(self):
        # Simulate that no matching records are found
        mock_response = mock.MagicMock()
        mock_response.RecordList = []
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        # Calling to delete a record will not throw an exception but will generate a warning
        self.client.del_txt_record(self.domain, self.record_name, self.record_content)
        self.mock_dnspod_sdk_client.DeleteRecord.assert_not_called()

    def test_del_txt_record_error(self):
        # Simulate the return of records when searching for record IDs, but throw an exception when deleting
        mock_record = mock.MagicMock()
        mock_record.RecordId = self.record_id
        mock_record.Name = self.record_name
        mock_record.Value = self.record_content
        mock_response = mock.MagicMock()
        mock_response.RecordList = [mock_record]
        self.mock_dnspod_sdk_client.DescribeRecordFilterList.return_value = mock_response

        self.mock_dnspod_sdk_client.DeleteRecord.side_effect = MockApiException("Delete error")

        # Should not throw exceptions, but errors will be logged
        self.client.del_txt_record(self.domain, self.record_name, self.record_content)


if __name__ == "__main__":
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
