#!/bin/bash
echo "GhostWatch demo — starts mock vulnerable target and runs full 125-probe scan"
echo "╔══════════════════════════════════════════╗"
echo "║         GHOSTWATCH AI SECURITY AGENT     ║"
echo "║     LLM Vulnerability Scanner v1.0       ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "► Step 1: Starting target AI endpoint..."
lsof -ti:8000 | xargs kill -9 2>/dev/null
sleep 1
cd ~/ghostwatch
python3 vulnerable_target.py > /dev/null 2>&1 &
sleep 2

echo ""
echo "► Step 2: GhostWatch Agent discovering & scanning..."
echo ""
python3 cli.py run --url http://127.0.0.1:8000/chat

echo ""
echo "► Step 3: AI Reasoning Engine analyzing findings..."
echo ""
python3 run_agent.py http://127.0.0.1:8000/chat

echo ""
echo "✅ GhostWatch scan complete."
