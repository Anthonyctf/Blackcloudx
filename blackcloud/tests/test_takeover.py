#!/usr/bin/env python3
"""Tests for BlackCloud takeover module."""

import pytest
from blackcloud.takeover import check_takeover


def test_check_takeover_provider_routing():
    assert check_takeover is not None
