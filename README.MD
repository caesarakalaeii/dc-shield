# 🛡️ DC-SHIELD: Discord Geoblocking and Cybersecurity Education & Awareness Platform

If you only want to get rid of GFX-Scammers on Discord here's what you need:

- **Basic Setup**: `https://dc-shield.caes.ar/your-dc-inv-code`
- **Custom Honeypot**: `https://dc-shield.caes.ar/your-dc-link/your-honey-pot-inv-code`

> **📚 Educational Demonstration for Cybersecurity Studies**
> This repository showcases security vulnerabilities and defense mechanisms for educational purposes as part of a cybersecurity degree program.

## ⚠️ IMPORTANT DISCLAIMER

**This is an EDUCATIONAL TOOL designed to demonstrate:**
- 🎯 Common web security vulnerabilities
- 🔍 Browser fingerprinting techniques
- 🌐 IP geolocation and tracking methods
- 🛡️ Privacy invasion capabilities
- 📊 Data collection techniques used by malicious actors

**⚖️ ETHICAL USE ONLY:** This tool is intended solely for educational purposes, security research, and raising awareness about digital privacy. Any malicious use is strictly prohibited and may violate laws in your jurisdiction.

## 🎓 Learning Objectives

This project helps cybersecurity students understand:
1. **Attack Vectors**: How malicious actors gather information
2. **Defense Mechanisms**: Protection against tracking and fingerprinting
3. **Privacy Implications**: The extent of data browsers can expose
4. **Security Headers**: Importance of proper security configurations
5. **Social Engineering**: How honeypots and deception work

## 🚀 Live Educational Demo

- **Basic Demo**: `https://dc-shield.laeii.de/your-dc-inv-code`
- **Advanced Honeypot**: `https://dc-shield.laeii.de/your-dc-link/your-honey-pot-inv-code`

> **Note**: The demo redirects users from specific countries (PK, IN) to honeypot servers.


## Installation with docker
1. Clone the repository:

   ```bash
   git clone https://github.com/caesarakalaeii/dc-shield/
   ```
2. Configure your settings by editing `config.json`. Ensure you have the following keys:

   - `default_server`: Default subdomain URL.
   - `honeypot_server`: Alternative server URL for specified countries.
   - `app_port`: Port this web server will be running on.
   - `test_flag`: Flag to redirect every second request, ignoring thee coutry code. used for testing.

3. Build the container:
   ```bash
   docker build -t dc-shield .
   ```

4. Run the container:
   ```bash
   docker run -p 5002:5002 dc-shield
   ```


## Installation without docker

1. Clone the repository:

   ```bash
   git clone https://github.com/caesarakalaeii/dc-shield/
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure your settings by editing `config.json`. Ensure you have the following keys:

   - `default_server`: Default subdomain URL.
   - `honeypot_server`: Alternative server URL for specified countries.
   - `app_port`: Port this web server will be running on.
   - `test_flag`: Flag to redirect every second request, ignoring thee coutry code. used for testing.

## Usage

Run the application:

```bash
python main.py
```

## Example

Suppose you have the following configuration:

```json
{
  "default_server": "https://example.com",
  "honeypot_server": "https://honeypot.example.com"
}
```

A user visiting from Pakistan or India will be redirected to `https://honeypot.example.com`, while users from other countries will be redirected to `https://example.com`.

## Dependencies

- `quart`: A Python web microframework.

## 🔍 Security Concepts Demonstrated

### 1. **IP Intelligence & Geolocation**
- Real IP extraction through proxy headers
- VPN/Tor detection using public blocklists
- Geographic-based access control
- ISP and data center identification

### 2. **Browser Fingerprinting**
- Canvas fingerprinting for unique identification
- WebGL hardware fingerprinting
- Audio context fingerprinting
- Font enumeration and detection
- Screen resolution and color depth analysis

### 3. **Device & System Profiling**
- User-Agent parsing and analysis
- Hardware capability detection (RAM, CPU cores)
- Battery status API exploitation
- Network information API usage
- Media device enumeration

### 4. **Privacy Invasion Techniques**
- Geolocation API exploitation
- Camera/microphone access attempts
- Clipboard reading attempts
- Local storage inspection
- Cookie analysis and tracking

### 5. **Social Engineering & Deception**
- Honeypot deployment strategies
- Geographic misdirection
- Fake service presentation
- Information disclosure through error messages

## 📈 Data Collected & Analyzed

The platform demonstrates collection of:
- **Network Data**: IP, ISP, VPN status, proxy detection
- **Location Data**: GPS coordinates, timezone, locale
- **Device Data**: OS, browser, hardware specs
- **Behavioral Data**: Mouse movements, typing patterns
- **Media Access**: Camera snapshots, microphone access
- **Storage Data**: Cookies, local storage, session data

## 🛡️ Defense Recommendations

Learn to protect yourself:
1. **Use Privacy-Focused Browsers**: Tor Browser, Brave
2. **Enable Tracking Protection**: uBlock Origin, Privacy Badger
3. **Disable JavaScript**: NoScript for high-security needs
4. **Use VPN Services**: But understand their limitations
5. **Regular Privacy Audits**: Check browser fingerprint regularly
6. **Permission Management**: Deny unnecessary permissions

## 🤝 Contributing

This is an educational project. Contributions that enhance the learning experience are welcome:
- Add new security demonstrations
- Improve educational documentation
- Create interactive tutorials
- Report security best practices

## ⚖️ Legal & Ethical Considerations

- **Consent**: Always obtain explicit consent before testing
- **Scope**: Only test on systems you own or have permission to test
- **Disclosure**: Report vulnerabilities responsibly
- **Education**: Use knowledge to protect, not exploit

## 📚 Educational Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Browser Security Handbook](https://code.google.com/archive/p/browsersec/)
- [Electronic Frontier Foundation](https://www.eff.org/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Panopticlick - Browser Fingerprinting](https://panopticlick.eff.org/)

## License

This project is licensed under the GNU Affero General Public License - see the [LICENSE](LICENSE) file for details.

## 🎓 Academic Citation

If you use this project for academic purposes, please cite:
```
DC-Shield: A Cybersecurity Educational Platform for Demonstrating Web Vulnerabilities
[Your University/Institution]
[Year]
```
