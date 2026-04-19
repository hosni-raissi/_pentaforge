#!/bin/bash
# Quick test runner for individual agents

set -e

echo "======================================================================"
echo "PENTAFORGE AGENT ISOLATION TESTS"
echo "======================================================================"
echo ""

# Test 1: Exploit Agent
echo "Running EXPLOIT AGENT TEST..."
echo ""
python3 -m server.test.test_exploit_agent

# Test 2: Recon Agent
echo ""
echo ""
echo "Running RECON AGENT TEST..."
echo ""
python3 -m server.test.test_recon_agent

echo ""
echo "======================================================================"
echo "ALL TESTS COMPLETED"
echo "======================================================================"
