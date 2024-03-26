# DC-SHIELD

A simple asynchronous Quart application for redirecting users based on their country.  
Will keep 90% of scammers away from your default discord.  

NOTE: Probably not a good idea if your community is based mainly in Pakistan and India.  

Ready to use solution under https://dc-shield.laeii.de/your-dc-inv-code  
Also with customizable honeypot: https://dc-shield.laeii.de/your-dc-link/your-honey-pot-inv-code  

## Installation

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

## License

This project is licensed under the GNU Affero General PublicLicense - see the [LICENSE](LICENSE) file for details.
