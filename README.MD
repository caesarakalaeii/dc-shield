# DC-SHIELD

A simple asynchronous Quart application for redirecting users based on their country using GeoIP data.
Will keeep 90% of scammers away from your default discord.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your_username/geoip-country-redirector.git
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Download the GeoLite2 Country database from [MaxMind](https://dev.maxmind.com/geoip/geoip2/geolite2/) and place it in the project directory with the name `GeoLite2-Country.mmdb`.

4. Configure your settings by editing `config.json`. Ensure you have the following keys:

   - `default_server`: Default subdomain URL.
   - `honeypot_server`: Alternative server URL for specified countries.

## Usage

Run the application:

```bash
python app.py
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

- `geoip2`: Python API for MaxMind GeoIP2 databases.
- `quart`: A Python web microframework.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.