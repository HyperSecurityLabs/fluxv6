# FluxV6 - Enhanced Network Load Testing Tool


### Overview

FluxV6 is an advanced network load testing tool that builds upon FluxV5 with additional email protocol testing capabilities. Designed by HyperSecurity, it provides comprehensive testing for web applications, APIs, and email services under realistic load conditions.



**Version:** Enhanced V6  
**Author:** Khaninkali  
**Group:** HyperSecurity  
**Purpose:** Advanced network and email load testing for authorized security testing

## New Features in FluxV6

### Email Protocol Testing
- **SMTP Testing:** Email sending capabilities with authentication
- **IMAP Testing:** Email retrieval and mailbox analysis
- **Auto-detection:** Automatic email server configuration for major providers
- **Authentication Support:** Username/password and app-specific passwords
- **Email Analysis:** Extract headers, attachments, and metadata

### Enhanced Traffic Simulation
- All FluxV5 features included
- Improved user agent database
- Enhanced geographic distribution
- Advanced timing patterns

## Configuration Options

### Core Parameters
```bash
-t, --target <URL>          Target URL to test
-c, --concurrent-users <NUM> Number of concurrent users (default: 100)
-d, --duration <SEC>         Test duration in seconds (default: 900)
--intensity <LEVEL>          Traffic intensity: low, medium, high (default: medium)
```

### Email Testing Options
```bash
--email-testing <BOOL>       Enable email protocol testing (default: false)
--email-server <SERVER>      Email server address (e.g., smtp.gmail.com)
--email-username <USER>      Email username for authentication
--email-password <PASS>      Email password or app password
--email-port <PORT>          Email port (SMTP: 587, IMAP: 993)
--email-count <NUM>          Number of emails to send/retrieve (default: 10)
```

### Traffic Options (FluxV5 Features)
```bash
--realistic-browsing <BOOL>  Enable realistic browsing patterns (default: true)
--mobile-traffic <BOOL>      Include mobile device traffic (default: true)
--bot-traffic <BOOL>         Include bot/crawler traffic (default: true)
--api-traffic <BOOL>         Include API client traffic (default: true)
--geographic-distribution <BOOL>  Simulate geographic distribution (default: true)
--time-patterns <BOOL>            Apply time-based traffic patterns (default: true)
```

## Usage Examples

### Basic Web Load Test
```bash
./fluxv6 --target https://example.com --concurrent-users 50 --duration 300
```

### Email Testing Only
```bash
./fluxv6  --email-testing --email-server smtp.gmail.com --email-username user@gmail.com --email-password apppassword --email-count 20
```

### Combined Web and Email Testing
```bash
./fluxv6 --target https://example.com --email-testing true --email-server smtp.gmail.com --email-username user@gmail.com --email-password apppassword --concurrent-users 100 --duration 600
```

### Auto-detect Email Server
```bash
./fluxv6  -t --email-testing --email-username user@gmail.com --email-password apppassword
```

## Email Server Configurations

### Supported Providers
The tool automatically detects configurations for:
- **Gmail:** smtp.gmail.com:587 / imap.gmail.com:993
- **Outlook:** smtp-mail.outlook.com:587 / outlook.office365.com:993
- **Yahoo:** smtp.mail.yahoo.com:587 / imap.mail.yahoo.com:993
- **iCloud:** smtp.mail.me.com:587 / imap.mail.me.com:993

### Manual Configuration
For custom email servers:
```bash
./fluxv6  -t --email-testing  --email-server custom.company.com --email-port 587 --email-username user@company.com --email-password password
```

## Email Testing Features

### SMTP Testing
- **Connection Testing:** Verify SMTP server connectivity
- **Authentication:** Test username/password authentication
- **Email Sending:** Send test emails with unique identifiers
- **Performance Metrics:** Measure send times and success rates
- **Error Handling:** Comprehensive error reporting and retry logic

### IMAP Testing
- **Mailbox Access:** Connect and authenticate to IMAP servers
- **Email Retrieval:** Fetch recent emails from INBOX
- **Header Parsing:** Extract From, Subject, Date, and other headers
- **Attachment Detection:** Identify emails with attachments
- **Read Status:** Track read/unread email status
- **Size Analysis:** Calculate total mailbox size and individual email sizes

### Email Analysis Results
```json
{
  "emails_sent": 10,
  "emails_retrieved": 25,
  "total_size_bytes": 1048576,
  "average_response_time_ms": 245.5,
  "errors": [],
  "extracted_info": [
    {
      "from": "sender@example.com",
      "subject": "Test Subject",
      "date": "2024-01-15 10:30:00",
      "size_bytes": 2048,
      "has_attachments": false,
      "is_unread": true
    }
  ]
}
```

## Technical Implementation

### Email Protocol Support
- **SMTP (Simple Mail Transfer Protocol):** For sending emails
- **IMAP (Internet Message Access Protocol):** For retrieving emails
- **TLS/SSL Support:** Secure connections for both protocols
- **Authentication Methods:** Username/password and app-specific passwords

### Security Considerations for Email Testing
⚠️ **IMPORTANT:** Email testing requires careful consideration:

- **Account Security:** Use app-specific passwords when available
- **Rate Limiting:** Respect email provider rate limits
- **Spam Policies:** Ensure compliance with anti-spam regulations
- **Privacy:** Test with dedicated test accounts only
- **Provider Terms:** Follow email provider terms of service

### Error Handling
- **Connection Failures:** Automatic retry with exponential backoff
- **Authentication Errors:** Clear error messages and troubleshooting tips
- **Rate Limiting:** Automatic delay adjustments when limits are reached
- **Network Issues:** Graceful handling of network interruptions

## Dependencies

```toml
[dependencies]
anyhow = "1.0"
base64 = "0.21"
clap = "4.0"
futures-util = "0.3"
imap = "3.0"
lettre = "0.11"
mailparse = "0.14"
rand = "0.8"
reqwest = "0.11"
serde_json = "1.0"
sha2 = "0.10"
tokio = { version = "1.0", features = ["full"] }
tracing = "0.1"
uuid = "1.0"
native-tls = "0.2"
```

## Performance Characteristics

### Email Testing Performance
- **SMTP Throughput:** Up to 10 emails/second (provider dependent)
- **IMAP Retrieval:** Up to 100 emails/second
- **Memory Usage:** Low (efficient email parsing)
- **Network Usage:** Moderate (email protocol overhead)

### Combined Testing
- **Web + Email:** Simultaneous testing of both protocols
- **Resource Sharing:** Efficient connection pooling across protocols
- **Coordinated Load:** Synchronized timing for realistic scenarios

## Security Best Practices

### Email Account Security
1. **Use App Passwords:** Generate app-specific passwords for testing
2. **Dedicated Accounts:** Use separate test email accounts
3. **Two-Factor Authentication:** Enable 2FA on primary accounts
4. **Regular Rotation:** Change test credentials regularly

### Network Security
1. **Authorized Testing:** Only test email systems you own
2. **Provider Compliance:** Follow email provider terms of service
3. **Rate Limiting:** Implement appropriate delays between requests
4. **Monitoring:** Monitor for abuse warnings or account suspensions

## Troubleshooting

### Common Email Issues

**Authentication Failures**
- Verify username and password correctness
- Use app-specific passwords for Gmail/Outlook
- Check for account lockouts or security alerts
- Ensure IMAP/SMTP is enabled in account settings

**Connection Timeouts**
- Verify server addresses and ports
- Check network connectivity to email servers
- Adjust timeout values for slow connections
- Test with alternative connection methods

**Rate Limiting**
- Reduce email count per test
- Increase delays between emails
- Monitor provider rate limit headers
- Use multiple test accounts if necessary

### Debug Mode
Enable verbose logging for detailed troubleshooting:
```bash
RUST_LOG=debug ./fluxv6 --email-testing true --email-server smtp.gmail.com --verbose
```

## Monitoring & Metrics

### Email Testing Metrics
- **Send Success Rate:** Percentage of successfully sent emails
- **Retrieval Success Rate:** Percentage of successfully retrieved emails
- **Average Response Time:** Mean time for email operations
- **Error Distribution:** Categorization of error types
- **Bandwidth Usage:** Total bytes transferred

### Combined Metrics
- **Protocol Distribution:** Breakdown of web vs email traffic
- **Resource Utilization:** CPU, memory, and network usage
- **Correlation Analysis:** Relationship between web and email load

## Compilation

```bash
# Compile with email features
cargo build --release --features "email-testing"

# Compile all features
cargo build --release --features "full"

# Run tests
cargo test --features "email-testing"

# Check code quality
cargo clippy --features "email-testing"
cargo fmt --check
```

## Integration with Other Tools

### API Integration
FluxV6 can be integrated with:
- **CI/CD Pipelines:** Automated load testing
- **Monitoring Systems:** Real-time metrics collection
- **Security Platforms:** Automated vulnerability scanning
- **Performance Tools:** Baseline performance measurement

### Output Formats
- **JSON:** Structured data for programmatic processing
- **CSV:** Spreadsheet-compatible format
- **Human-readable:** Formatted reports for manual review

## Contributing

1. Fork the repository
2. Create a feature branch for email enhancements
3. Implement changes with comprehensive tests
4. Ensure email provider compatibility
5. Submit pull request with documentation

## License

This tool is part of the HyperSecurity toolkit and is released under(GPL) the appropriate open-source license for security research tools.

## Disclaimer

This software is provided for educational and authorized security testing purposes only. Users are responsible for ensuring compliance with applicable laws, regulations, and email provider terms of service. The authors assume no liability for misuse or unauthorized use.
