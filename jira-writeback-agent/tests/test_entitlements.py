"""
Regression test to ensure Jira Writeback agent decrements trial_writeback_runs_remaining,
NOT trial_testplan_runs_remaining or trial_requirements_runs_remaining.

This test prevents the bug where Jira writeback agent was importing entitlements from
the wrong repo and decrementing the wrong counter.
"""
import pytest
from unittest.mock import Mock, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.entitlements import consume_trial_run, check_entitlement


def test_consume_trial_run_decrements_writeback_not_testplan():
    """Test that consume_trial_run decrements writeback counter, not testplan or requirements."""
    # Create a mock tenant with all counters at 3
    mock_tenant = Mock()
    mock_tenant.id = "test-tenant-id"
    mock_tenant.subscription_status = "Trial"
    mock_tenant.trial_requirements_runs_remaining = 3
    mock_tenant.trial_testplan_runs_remaining = 3
    mock_tenant.trial_writeback_runs_remaining = 3
    
    # Create a mock DB session
    mock_db = Mock()
    mock_db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_tenant
    
    # Call consume_trial_run
    consume_trial_run(mock_db, "test-tenant-id")
    
    # Verify writeback counter was decremented
    assert mock_tenant.trial_writeback_runs_remaining == 2, \
        "trial_writeback_runs_remaining should be decremented from 3 to 2"
    
    # Verify testplan counter was NOT touched
    assert mock_tenant.trial_testplan_runs_remaining == 3, \
        "trial_testplan_runs_remaining should remain 3 (not decremented)"
    
    # Verify requirements counter was NOT touched
    assert mock_tenant.trial_requirements_runs_remaining == 3, \
        "trial_requirements_runs_remaining should remain 3 (not decremented)"
    
    # Verify commit was called
    mock_db.commit.assert_called_once()


def test_check_entitlement_checks_writeback_counter():
    """Test that check_entitlement checks writeback counter, not testplan or requirements."""
    # Create a mock tenant with writeback=2, testplan=3, requirements=3
    mock_tenant = Mock()
    mock_tenant.id = "test-tenant-id"
    mock_tenant.subscription_status = "Trial"
    mock_tenant.trial_requirements_runs_remaining = 3
    mock_tenant.trial_testplan_runs_remaining = 3
    mock_tenant.trial_writeback_runs_remaining = 2
    
    # Create a mock DB session
    mock_db = Mock()
    mock_db.query.return_value.filter.return_value.first.return_value = mock_tenant
    
    # Call check_entitlement
    allowed, reason, status, remaining = check_entitlement(mock_db, "test-tenant-id")
    
    # Verify it checks writeback counter (remaining should be 2, not 3)
    assert remaining == 2, \
        "check_entitlement should return trial_writeback_runs_remaining (2), not testplan (3) or requirements (3)"
    assert allowed is True, "Should be allowed when writeback remaining > 0"
    assert status == "Trial", "Status should be Trial"


def test_consume_trial_run_paywall_flip_when_all_zero():
    """Test that paywall flips only when ALL three counters are 0."""
    # Create a mock tenant with requirements=0, testplan=0, writeback=1
    mock_tenant = Mock()
    mock_tenant.id = "test-tenant-id"
    mock_tenant.subscription_status = "Trial"
    mock_tenant.trial_requirements_runs_remaining = 0
    mock_tenant.trial_testplan_runs_remaining = 0
    mock_tenant.trial_writeback_runs_remaining = 1
    
    # Create a mock DB session
    mock_db = Mock()
    mock_db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_tenant
    
    # Call consume_trial_run (should decrement writeback to 0)
    consume_trial_run(mock_db, "test-tenant-id")
    
    # Verify writeback is now 0
    assert mock_tenant.trial_writeback_runs_remaining == 0
    
    # Verify paywall was flipped (all three are now 0)
    assert mock_tenant.subscription_status == "Paywalled", \
        "Should flip to Paywalled when all three counters reach 0"
    
    # Verify commit was called
    mock_db.commit.assert_called_once()
