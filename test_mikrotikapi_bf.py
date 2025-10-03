#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Unit tests for MikrotikAPI-BF

Run with: pytest test_mikrotikapi_bf.py -v
"""

import pytest
import tempfile
import os
from pathlib import Path

# Import modules to test
from _api import Api
from _log import Log
from _export import ResultExporter
from _progress import ProgressBar, SpinnerProgress
from _retry import RetryStrategy, CircuitBreaker, retry, circuit_breaker
from _discovery import MikrotikDiscovery

class TestApi:
    """Test API module"""
    
    def test_encode_length_small(self):
        """Test encoding of small length"""
        api = Api("127.0.0.1", 8728)
        encoded = api.encode_length(10)
        assert encoded == bytes([10])
    
    def test_encode_length_medium(self):
        """Test encoding of medium length"""
        api = Api("127.0.0.1", 8728)
        encoded = api.encode_length(200)
        assert len(encoded) == 2
    
    def test_api_initialization(self):
        """Test API initialization"""
        api = Api("192.168.88.1", 8728)
        assert api.host == "192.168.88.1"
        assert api.port == 8728
        assert api.sock is None


class TestLog:
    """Test logging module"""
    
    def test_log_initialization(self):
        """Test log initialization"""
        log = Log(verbose=False, verbose_all=False)
        assert log.verbose == False
        assert log.verbose_all == False
    
    def test_log_timestamp(self):
        """Test timestamp generation"""
        log = Log()
        timestamp = log.timestamp()
        assert isinstance(timestamp, str)
        assert ":" in timestamp


class TestResultExporter:
    """Test export module"""
    
    @pytest.fixture
    def sample_results(self):
        """Sample results for testing"""
        return [
            {'user': 'admin', 'pass': 'password123', 'services': ['api', 'ftp']},
            {'user': 'manager', 'pass': 'mikrotik', 'services': ['api']}
        ]
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for exports"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_export_json(self, sample_results, temp_dir):
        """Test JSON export"""
        exporter = ResultExporter(sample_results, "192.168.88.1", output_dir=temp_dir)
        filename = exporter.export_json()
        
        assert filename.exists()
        assert filename.suffix == ".json"
    
    def test_export_csv(self, sample_results, temp_dir):
        """Test CSV export"""
        exporter = ResultExporter(sample_results, "192.168.88.1", output_dir=temp_dir)
        filename = exporter.export_csv()
        
        assert filename.exists()
        assert filename.suffix == ".csv"
    
    def test_export_xml(self, sample_results, temp_dir):
        """Test XML export"""
        exporter = ResultExporter(sample_results, "192.168.88.1", output_dir=temp_dir)
        filename = exporter.export_xml()
        
        assert filename.exists()
        assert filename.suffix == ".xml"
    
    def test_export_txt(self, sample_results, temp_dir):
        """Test TXT export"""
        exporter = ResultExporter(sample_results, "192.168.88.1", output_dir=temp_dir)
        filename = exporter.export_txt()
        
        assert filename.exists()
        assert filename.suffix == ".txt"
    
    def test_export_all(self, sample_results, temp_dir):
        """Test export all formats"""
        exporter = ResultExporter(sample_results, "192.168.88.1", output_dir=temp_dir)
        files = exporter.export_all()
        
        assert len(files) == 4
        assert all(f.exists() for f in files.values())


class TestProgressBar:
    """Test progress bar module"""
    
    def test_progress_initialization(self):
        """Test progress bar initialization"""
        progress = ProgressBar(total=100)
        assert progress.total == 100
        assert progress.current == 0
        assert progress.success_count == 0
    
    def test_progress_update(self):
        """Test progress update"""
        progress = ProgressBar(total=100)
        progress.update(10)
        assert progress.current == 10
    
    def test_progress_success(self):
        """Test progress with success"""
        progress = ProgressBar(total=100)
        progress.update(1, success=True)
        assert progress.success_count == 1
    
    def test_spinner_initialization(self):
        """Test spinner initialization"""
        spinner = SpinnerProgress("Testing")
        assert spinner.message == "Testing"
        assert spinner.running == False


class TestRetryStrategy:
    """Test retry mechanism"""
    
    def test_retry_success(self):
        """Test retry on success"""
        call_count = [0]
        
        @retry(max_attempts=3)
        def success_function():
            call_count[0] += 1
            return "success"
        
        result = success_function()
        assert result == "success"
        assert call_count[0] == 1
    
    def test_retry_failure(self):
        """Test retry on failure"""
        call_count = [0]
        
        @retry(max_attempts=3, initial_delay=0.1)
        def fail_function():
            call_count[0] += 1
            raise Exception("Test error")
        
        with pytest.raises(Exception):
            fail_function()
        
        assert call_count[0] == 3
    
    def test_retry_eventual_success(self):
        """Test retry with eventual success"""
        call_count = [0]
        
        @retry(max_attempts=5, initial_delay=0.1)
        def eventual_success():
            call_count[0] += 1
            if call_count[0] < 3:
                raise Exception("Not yet")
            return "success"
        
        result = eventual_success()
        assert result == "success"
        assert call_count[0] == 3


class TestCircuitBreaker:
    """Test circuit breaker"""
    
    def test_circuit_closed(self):
        """Test circuit in closed state"""
        breaker = CircuitBreaker(failure_threshold=3)
        assert breaker.state == CircuitBreaker.STATE_CLOSED
    
    def test_circuit_opens_on_failures(self):
        """Test circuit opens after failures"""
        call_count = [0]
        
        @circuit_breaker(failure_threshold=3, timeout=1)
        def failing_function():
            call_count[0] += 1
            raise Exception("Test error")
        
        # Cause failures
        for _ in range(3):
            try:
                failing_function()
            except:
                pass
        
        # Circuit should be open now
        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            failing_function()


class TestMikrotikDiscovery:
    """Test discovery module"""
    
    def test_discovery_initialization(self):
        """Test discovery initialization"""
        discovery = MikrotikDiscovery(timeout=2, threads=10)
        assert discovery.timeout == 2
        assert discovery.threads == 10
    
    def test_port_definitions(self):
        """Test Mikrotik port definitions"""
        assert MikrotikDiscovery.MIKROTIK_PORTS['api'] == 8728
        assert MikrotikDiscovery.MIKROTIK_PORTS['winbox'] == 8291


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

