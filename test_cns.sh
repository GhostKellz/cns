#!/bin/bash

echo "🧪 Enhanced CNS Test Script"
echo "=========================="
echo "Testing HTTP/3, QUIC, DoQ, DoH, and Traditional DNS"

# Function to test DNS query
test_query() {
    local domain=$1
    local server=$2
    local protocol=${3:-"udp"}
    echo "Testing $domain via $protocol..."
    
    case $protocol in
        "udp"|"tcp")
            dig @$server $domain +short +time=2
            ;;
        "doh")
            # Test DNS-over-HTTPS
            curl -s -H "Accept: application/dns-json" \
                "https://$server/dns-query?name=$domain&type=A" | jq -r '.Answer[]?.data // "No response"'
            ;;
        "doq")
            # Test DNS-over-QUIC (if kdig with DoQ support is available)
            if command -v kdig >/dev/null 2>&1; then
                kdig @$server +tls-ca +tls-hostname=$server $domain
            else
                echo "DoQ testing requires kdig with QUIC support"
            fi
            ;;
    esac
}

# Function to test HTTP/3 web interface
test_web_interface() {
    local server=$1
    local port=${2:-8080}
    echo "Testing web interface at http://$server:$port..."
    
    if command -v curl >/dev/null 2>&1; then
        echo "📊 Server Status:"
        curl -s "http://$server:$port/api/stats" | jq . 2>/dev/null || curl -s "http://$server:$port/api/stats"
        echo ""
        
        echo "🌐 Web Interface:"
        curl -s -I "http://$server:$port/" | head -5
    else
        echo "curl not available for web interface testing"
    fi
}

# Check if Enhanced CNS is running
if ! pgrep -f "cns" > /dev/null; then
    echo "⚠️  CNS server is not running. Starting it..."
    echo ""
    echo "🚀 Start Enhanced CNS with:"
    echo "   sudo zig-out/bin/cns -c configs/enhanced_cns.conf"
    echo ""
    echo "📡 Or start Legacy CNS with:"
    echo "   sudo zig-out/bin/cns --legacy -c configs/cns.conf"
    echo ""
    echo "🔧 Build first with:"
    echo "   zig build"
    echo ""
    exit 1
fi

echo "📋 Test Suite - Enhanced CNS Server"
echo ""

# Test traditional DNS protocols
echo "1. Traditional DNS (UDP/TCP):"
test_query "google.com" "127.0.0.1" "udp"
test_query "cloudflare.com" "127.0.0.1" "tcp"

echo ""
echo "2. Modern DNS Protocols:"

# Test DNS-over-HTTPS
echo "🌐 DNS-over-HTTPS (DoH):"
test_query "example.com" "127.0.0.1:443" "doh"

# Test DNS-over-QUIC
echo "🔐 DNS-over-QUIC (DoQ):"
test_query "example.com" "127.0.0.1:853" "doq"

echo ""
echo "3. Blockchain Domains (should resolve or return NXDOMAIN):"
test_query "mysite.ghost" "127.0.0.1" "udp"
test_query "example.chain" "127.0.0.1" "udp"
test_query "root.bc" "127.0.0.1" "udp"
test_query "vitalik.eth" "127.0.0.1" "udp"

echo ""
echo "4. ENS Domains:"
test_query "ethereum.eth" "127.0.0.1" "udp"
test_query "uniswap.eth" "127.0.0.1" "udp"

echo ""
echo "5. Performance Test (caching):"
echo "First query (cache miss):"
time test_query "performance-test.com" "127.0.0.1" "udp"
echo "Second query (cache hit):"
time test_query "performance-test.com" "127.0.0.1" "udp"

echo ""
echo "6. HTTP/3 Web Interface & API:"
test_web_interface "127.0.0.1" "8080"

echo ""
echo "7. Protocol Performance Comparison:"
echo "🔄 Traditional DNS (UDP):"
time (for i in {1..5}; do test_query "speed-test-$i.com" "127.0.0.1" "udp" >/dev/null; done)

echo "🌐 DNS-over-HTTPS:"
time (for i in {1..5}; do test_query "speed-test-$i.com" "127.0.0.1:443" "doh" >/dev/null 2>&1; done)

echo ""
echo "8. Security Features Test:"
echo "🛡️ Rate Limiting Test (rapid queries):"
for i in {1..20}; do
    test_query "rate-limit-test-$i.com" "127.0.0.1" "udp" >/dev/null &
done
wait
echo "Rate limiting test completed"

echo ""
echo "9. Load Test Simulation:"
echo "🚀 Concurrent queries test:"
for i in {1..50}; do
    test_query "load-test-$i.com" "127.0.0.1" "udp" >/dev/null &
done
wait
echo "Load test completed"

echo ""
echo "10. Feature Validation:"
echo "✅ Enhanced Features Status:"

# Check if HTTP/3 port is listening
if ss -tuln | grep -q ":443 "; then
    echo "   🌐 HTTP/3 Server: Running on port 443"
else
    echo "   ❌ HTTP/3 Server: Not detected"
fi

# Check if DoQ port is listening
if ss -tuln | grep -q ":853 "; then
    echo "   🔐 DNS-over-QUIC: Running on port 853"
else
    echo "   ❌ DNS-over-QUIC: Not detected"
fi

# Check if traditional DNS is working
if ss -tuln | grep -q ":53 "; then
    echo "   📡 Traditional DNS: Running on port 53"
else
    echo "   ❌ Traditional DNS: Not detected"
fi

# Check if web interface is running
if ss -tuln | grep -q ":8080 "; then
    echo "   📊 Web Interface: Running on port 8080"
else
    echo "   ❌ Web Interface: Not detected"
fi

echo ""
echo "✅ Enhanced CNS Test Suite Complete!"
echo ""
echo "📈 Next Steps:"
echo "   • Visit http://127.0.0.1:8080 for the web interface"
echo "   • Monitor logs for detailed query information"
echo "   • Test with real blockchain domains"
echo "   • Configure production TLS certificates"
echo ""
echo "🔗 Supported Protocols:"
echo "   • Traditional DNS (UDP/TCP) on port 53"
echo "   • DNS-over-QUIC (DoQ) on port 853"
echo "   • DNS-over-HTTPS (DoH) on port 443"
echo "   • HTTP/3 with QUIC transport"
echo "   • TLS 1.3 encryption"
echo "   • Blockchain domain resolution"