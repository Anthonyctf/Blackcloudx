#!/usr/bin/env python3
"""Tests for BlackCloud policy module."""

import pytest
from blackcloud.policy import _parse_acl_xml, _parse_lifecycle_xml


def test_parse_acl_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner-id</ID><DisplayName>owner</DisplayName></Owner>
  <AccessControlList>
    <Grant>
      <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser" URI="uri"><DisplayName>user</DisplayName></Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>"""
    result = _parse_acl_xml(xml)
    assert len(result["grants"]) == 1
    assert result["grants"][0]["permission"] == "READ"


def test_parse_lifecycle_xml():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Rule>
    <ID>rule1</ID>
    <Status>Enabled</Status>
    <Prefix>logs/</Prefix>
  </Rule>
</LifecycleConfiguration>"""
    rules = _parse_lifecycle_xml(xml)
    assert len(rules) == 1
    assert rules[0]["id"] == "rule1"
